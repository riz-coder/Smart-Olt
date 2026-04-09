from django.conf import settings
from django.db import models


class OLT(models.Model):
    name = models.CharField(max_length=100, unique=True)  # e.g., "Main OLT"
    ip_address = models.GenericIPAddressField(unique=True)
    port = models.IntegerField(default=23, help_text='Telnet port')
    snmp_port = models.IntegerField(default=161, help_text='SNMP UDP port')
    snmp_community = models.CharField(max_length=100, default='public')
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=100)  # We'll encrypt later
    vendor = models.CharField(max_length=20, default='Huawei')  # GPON/EPON
    hardware_version = models.CharField(max_length=100, blank=True, default='')
    sw_version = models.CharField(max_length=100, blank=True, default='')
    snmp_last_status = models.CharField(max_length=300, blank=True, default='')
    snmp_last_synced_at = models.DateTimeField(blank=True, null=True)
    olt_cards_cache = models.JSONField(default=list, blank=True)
    olt_cards_status = models.CharField(max_length=300, blank=True, default='')
    olt_cards_refreshed_at = models.DateTimeField(blank=True, null=True)
    pon_ports_cache = models.JSONField(default=list, blank=True)
    pon_ports_status = models.CharField(max_length=300, blank=True, default='')
    pon_ports_refreshed_at = models.DateTimeField(blank=True, null=True)
    uplink_cache = models.JSONField(default=list, blank=True)
    uplink_status = models.CharField(max_length=300, blank=True, default='')
    uplink_refreshed_at = models.DateTimeField(blank=True, null=True)
    vlan_cache = models.JSONField(default=list, blank=True)
    vlan_status = models.CharField(max_length=300, blank=True, default='')
    vlan_refreshed_at = models.DateTimeField(blank=True, null=True)
    dba_profile_cache = models.JSONField(default=list, blank=True)
    dba_profile_status = models.CharField(max_length=300, blank=True, default='')
    dba_profile_refreshed_at = models.DateTimeField(blank=True, null=True)
    autofind_onu_count = models.PositiveIntegerField(default=0)
    autofind_status = models.CharField(max_length=300, blank=True, default='')
    autofind_refreshed_at = models.DateTimeField(blank=True, null=True)
    dashboard_uptime = models.CharField(max_length=120, blank=True, default='')
    dashboard_temperature = models.CharField(max_length=32, blank=True, default='')
    dashboard_snapshot_refreshed_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class OLTLoginHistory(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='login_history')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    username = models.CharField(max_length=150, blank=True, default='')
    action = models.CharField(max_length=50, default='login')
    onu = models.CharField(max_length=120, blank=True, default='')
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    details = models.CharField(max_length=300, blank=True, default='')
    logged_in_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-logged_in_at']

    def __str__(self):
        who = self.username or 'unknown'
        return f"{self.olt.name} | {who} | {self.action}"


class ConfiguredONU(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='configured_onus')
    frame = models.PositiveIntegerField(default=0)
    slot = models.PositiveIntegerField()
    port = models.PositiveIntegerField()
    ont_id = models.PositiveIntegerField()
    sn = models.CharField(max_length=64, blank=True, default='')
    control_flag = models.CharField(max_length=32, blank=True, default='')
    run_state = models.CharField(max_length=32, blank=True, default='')
    config_state = models.CharField(max_length=32, blank=True, default='')
    match_state = models.CharField(max_length=32, blank=True, default='')
    protect_side = models.CharField(max_length=32, blank=True, default='')
    description = models.CharField(max_length=255, blank=True, default='')
    address = models.CharField(max_length=255, blank=True, default='')
    contact = models.CharField(max_length=64, blank=True, default='')
    onu_rx = models.CharField(max_length=32, blank=True, default='')
    olt_rx = models.CharField(max_length=32, blank=True, default='')
    tx_power = models.CharField(max_length=32, blank=True, default='')
    signal_bucket = models.CharField(max_length=16, blank=True, default='', db_index=True)
    derived_status = models.CharField(max_length=32, blank=True, default='', db_index=True)
    status_source = models.CharField(max_length=32, blank=True, default='')
    status_first_seen_at = models.DateTimeField(blank=True, null=True)
    status_updated_at = models.DateTimeField(blank=True, null=True)
    raw_line = models.TextField(blank=True, default='')
    synced_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['olt_id', 'slot', 'port', 'ont_id']
        constraints = [
            models.UniqueConstraint(
                fields=['olt', 'frame', 'slot', 'port', 'ont_id'],
                name='unique_configured_onu_per_olt_port',
            )
        ]

    def __str__(self):
        return f"{self.olt.name} {self.frame}/{self.slot}/{self.port}:{self.ont_id}"


class ONUTrapEvent(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='onu_trap_events')
    slot = models.PositiveIntegerField()
    port = models.PositiveIntegerField()
    ont_id = models.PositiveIntegerField()
    alarm_key = models.CharField(max_length=96)
    alarm_code = models.CharField(max_length=64, blank=True, default='')
    alarm_name = models.CharField(max_length=255, blank=True, default='')
    mapped_status = models.CharField(max_length=32, blank=True, default='', db_index=True)
    severity = models.CharField(max_length=32, blank=True, default='')
    is_active = models.BooleanField(default=True, db_index=True)
    raw_payload = models.TextField(blank=True, default='')
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-last_seen']
        constraints = [
            models.UniqueConstraint(
                fields=['olt', 'slot', 'port', 'ont_id', 'alarm_key'],
                name='unique_onu_trap_event_per_alarm',
            )
        ]
        indexes = [
            models.Index(fields=['olt', 'slot', 'port', 'ont_id', 'is_active'], name='onu_trap_active_lookup_idx'),
        ]

    def __str__(self):
        return f"{self.olt.name} {self.slot}/{self.port}:{self.ont_id} {self.alarm_key}"


class ONUOpticalSample(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='onu_optical_samples')
    slot = models.PositiveIntegerField()
    port = models.PositiveIntegerField()
    ont_id = models.PositiveIntegerField()
    onu_rx = models.CharField(max_length=32, blank=True, default='')
    olt_rx = models.CharField(max_length=32, blank=True, default='')
    tx_power = models.CharField(max_length=32, blank=True, default='')
    sampled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sampled_at']
        indexes = [
            models.Index(fields=['olt', 'slot', 'port', 'ont_id', 'sampled_at'], name='onu_sample_lookup_idx'),
        ]

    def __str__(self):
        return f"{self.olt.name} {self.slot}/{self.port}:{self.ont_id} @ {self.sampled_at}"


class DashboardStatusSample(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='dashboard_status_samples', null=True, blank=True)
    total_onus = models.PositiveIntegerField(default=0)
    online_onus = models.PositiveIntegerField(default=0)
    offline_onus = models.PositiveIntegerField(default=0)
    admin_disabled = models.PositiveIntegerField(default=0)
    power_failure = models.PositiveIntegerField(default=0)
    loss_of_signal = models.PositiveIntegerField(default=0)
    signal_warn = models.PositiveIntegerField(default=0)
    signal_bad = models.PositiveIntegerField(default=0)
    sampled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sampled_at']
        indexes = [
            models.Index(fields=['olt', 'sampled_at'], name='dash_status_olt_time_idx'),
            models.Index(fields=['sampled_at'], name='dash_status_time_idx'),
        ]

    def __str__(self):
        scope = self.olt.name if self.olt_id else 'All OLTs'
        return f"{scope} @ {self.sampled_at}"
