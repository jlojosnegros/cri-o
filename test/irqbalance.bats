#!/usr/bin/env bats
# vim: set syntax=sh:

load helpers

function detect_irqbalance_config() {
	# debian/ubuntu
	[ -f /etc/default/irqbalance ] && echo "/etc/default/irqbalance"
	# fedora/centos/RHEL
	[ -f /etc/sysconfig/irqbalance ] && echo "/etc/sysconfig/irqbalance"
	# default
	echo ""
}

function setup_file() {
	if ! command -v irqbalance > /dev/null; then
		skip "irqbalance not found."
	fi
	IRQBALANCE_CONF=$(detect_irqbalance_config)
	if [ -z "$IRQBALANCE_CONF" ]; then
		echo "error: unable to find irqbalance config file"
		return 1
	fi
	CONFIGLET="$CRIO_CONFIG_DIR/99-irqbalance.conf"

	mkdir -p "/etc/sysconfig"
	BANNEDCPUS_CONF="/etc/sysconfig/orig_irq_banned_cpus"

	export IRQBALANCE_CONF
	export CONFIGLET
	export BANNEDCPUS_CONF

	export BATS_NO_PARALLELIZE_WITHIN_FILE=true
}

function setup() {
	setup_test
	stop_crio
	# we don't unconditionally restore because the irqbalance package may be missing
	# from the test system. if this is the case, one less thing to worry about, we can't
	# pollute the system state anyway :)
	if [ -f "$IRQBALANCE_CONF" ]; then
		cp -v "$IRQBALANCE_CONF" "$IRQBALANCE_CONF".bkp
	else
		# placeholder to make the rest of the suite simpler.
		touch "$IRQBALANCE_CONF"
		touch /tmp/.test_owns_irqbalance_conf
	fi
	if [ -f "$BANNEDCPUS_CONF" ]; then
		cp -v "$BANNEDCPUS_CONF" "$BANNEDCPUS_CONF".bkp
	else
		# empty file is fine and meaningful
		touch "$BANNEDCPUS_CONF"
		touch /tmp/.test_owns_bannedcpus_conf
	fi
}

function teardown() {
	cleanup_test
	stop_crio
	# see setup about why we have these conditionals
	if [ -f "$IRQBALANCE_CONF".bkp ]; then
		mv -v "$IRQBALANCE_CONF".bkp "$IRQBALANCE_CONF"
	elif [ -f /tmp/.test_owns_irqbalance_conf ]; then
		rm -f "$IRQBALANCE_CONF"
		rm -f /tmp/.test_owns_irqbalance_conf
	fi

	if [ -f "$BANNEDCPUS_CONF".bkp ]; then
		mv -v "$BANNEDCPUS_CONF".bkp "$BANNEDCPUS_CONF"
	elif [ -f /tmp/.test_owns_bannedcpus_conf ]; then
		rm -f "$BANNEDCPUS_CONF"
		rm -f /tmp/.test_owns_bannedcpus_conf
	fi
}

@test "irqbalance cpu ban list save" {
	# given
	if ! grep -Eq '^[1,3,7,f]{1,}$' /proc/irq/default_smp_affinity; then
		skip "requires default IRQ smp affinity (not banned CPUs)"
	fi
	[ -f "$CONFIGLET" ] && rm -f "$CONFIGLET"

	[ -f "$BANNEDCPUS_CONF" ] && rm -f "$BANNEDCPUS_CONF"

	local expected_banned_cpus
	expected_banned_cpus=$(sed -n 's/^IRQBALANCE_BANNED_CPUS=\"\?\([^\"]*\)\"\?/\1/p' "$IRQBALANCE_CONF")

	# when
	OVERRIDE_OPTIONS="--irqbalance-config-file ${IRQBALANCE_CONF}" start_crio

	# then
	if [ ! -f "$BANNEDCPUS_CONF" ]; then
		echo "error: ${BANNEDCPUS_CONF} file should have been created by CRI-o"
		return 2
	fi

	local banned_cpus
	banned_cpus=$(cat "$BANNEDCPUS_CONF")

	[ "$expected_banned_cpus" == "$banned_cpus" ]
}

@test "irqbalance cpu ban list restore - default" {
	# given
	if ! grep -Eq '^[1,3,7,f]{1,}$' /proc/irq/default_smp_affinity; then
		skip "requires default IRQ smp affinity (not banned CPUs)"
	fi
	[ -f "$CONFIGLET" ] && rm -f "$CONFIGLET"

	echo "IRQBALANCE_BANNED_CPUS=\"0\"" > "$IRQBALANCE_CONF"

	local banned_cpus_for_conf
	banned_cpus_for_conf=$(cat /proc/irq/default_smp_affinity)
	echo "$banned_cpus_for_conf" > "$BANNEDCPUS_CONF"

	# when
	OVERRIDE_OPTIONS="--irqbalance-config-file ${IRQBALANCE_CONF}" start_crio

	# then
	local banned_cpus
	banned_cpus=$(sed -n 's/^IRQBALANCE_BANNED_CPUS=\"\?\([^\"]*\)\"\?/\1/p' "$IRQBALANCE_CONF")

	[ "$banned_cpus_for_conf" == "$banned_cpus" ]
}

# disable restore file, check it does NOT clear the irqbalance config
@test "irqbalance cpu ban list restore - disable and file missing" {
	# given
	if ! grep -Eq '^[1,3,7,f]{1,}$' /proc/irq/default_smp_affinity; then
		skip "requires default IRQ smp affinity (not banned CPUs)"
	fi
	[ -f "$CONFIGLET" ] && rm -f "$CONFIGLET"

	local expected_banned_cpus
	expected_banned_cpus=$(sed -n 's/^IRQBALANCE_BANNED_CPUS=\"\?\([^\"]*\)\"\?/\1/p' "$IRQBALANCE_CONF")

	[ -f "$BANNEDCPUS_CONF" ] && rm -f "$BANNEDCPUS_CONF"

	# when
	OVERRIDE_OPTIONS="--irqbalance-config-file ${IRQBALANCE_CONF} --irqbalance-config-restore-file disable" start_crio

	# then
	local banned_cpus
	banned_cpus=$(sed -n 's/^IRQBALANCE_BANNED_CPUS=\"\?\([^\"]*\)\"\?/\1/p' "$IRQBALANCE_CONF")

	[ "$expected_banned_cpus" == "$banned_cpus" ] && [ ! -f "$BANNEDCPUS_CONF" ]
}

@test "irqbalance cpu ban list restore - disable" {
	# given
	if ! grep -Eq '^[1,3,7,f]{1,}$' /proc/irq/default_smp_affinity; then
		skip "requires default IRQ smp affinity (not banned CPUs)"
	fi
	[ -f "$CONFIGLET" ] && rm -f "$CONFIGLET"

	local expected_banned_cpus
	expected_banned_cpus=$(sed -n 's/^IRQBALANCE_BANNED_CPUS=\"\?\([^\"]*\)\"\?/\1/p' "$IRQBALANCE_CONF")

	local banned_cpus_for_conf
	banned_cpus_for_conf=$(cat /proc/irq/default_smp_affinity)
	echo "$banned_cpus_for_conf" > "$BANNEDCPUS_CONF"

	# when
	OVERRIDE_OPTIONS="--irqbalance-config-file ${IRQBALANCE_CONF} --irqbalance-config-restore-file disable" start_crio

	# then
	local banned_cpus
	banned_cpus=$(sed -n 's/^IRQBALANCE_BANNED_CPUS=\"\?\([^\"]*\)\"\?/\1/p' "$IRQBALANCE_CONF")

	[ "$expected_banned_cpus" == "$banned_cpus" ]
}

# explicit restore file, check it does SET the irqbalance config accordingly
@test "irqbalance cpu ban list restore - explicit file" {
	# given
	if ! grep -Eq '^[1,3,7,f]{1,}$' /proc/irq/default_smp_affinity; then
		skip "requires default IRQ smp affinity (not banned CPUs)"
	fi
	[ -f "$CONFIGLET" ] && rm -f "$CONFIGLET"

	[ -f "$BANNEDCPUS_CONF" ] && rm -f "$BANNEDCPUS_CONF"

	echo "IRQBALANCE_BANNED_CPUS=\"0\"" > "$IRQBALANCE_CONF"

	local irqbalance_restore_file
	irqbalance_restore_file="$(mktemp /tmp/irq-restore.XXXXXXXXX)"

	cat /proc/irq/default_smp_affinity > "$irqbalance_restore_file"

	local banned_cpus_for_restore
	banned_cpus_for_restore=$(cat "$irqbalance_restore_file")

	# when
	OVERRIDE_OPTIONS="--irqbalance-config-file ${IRQBALANCE_CONF} --irqbalance-config-restore-file ${irqbalance_restore_file}" start_crio

	# then
	local banned_cpus
	banned_cpus=$(sed -n 's/^IRQBALANCE_BANNED_CPUS=\"\?\([^\"]*\)\"\?/\1/p' "$IRQBALANCE_CONF")

	[ "$banned_cpus_for_restore" == "$banned_cpus" ] && [ ! -f "$BANNEDCPUS_CONF" ]
}
