import re

from django.conf import settings
from django.db import models
from django.utils import timezone


class OLT(models.Model):
    PRICING_DEMO = "demo"
    PRICING_STANDARD = "standard"
    PRICING_CUSTOM = "custom"
    PRICING_CHOICES = [
        (PRICING_DEMO, "Demo Account"),
        (PRICING_STANDARD, "Standard (1 month)"),
        (PRICING_CUSTOM, "Custom"),
    ]

    name = models.CharField(max_length=100, unique=True)  # e.g., "Main OLT"
    ip_address = models.GenericIPAddressField(unique=True)
    port = models.IntegerField(default=23, help_text='Telnet port')
    snmp_port = models.IntegerField(default=161, help_text='SNMP UDP port')
    snmp_community = models.CharField(max_length=100, default='public')
    snmp_write_community = models.CharField(max_length=100, blank=True, default='')
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=100)  # We'll encrypt later
    vendor = models.CharField(max_length=20, default='Huawei')  # GPON/EPON
    hardware_version = models.CharField(max_length=100, blank=True, default='')
    sw_version = models.CharField(max_length=100, blank=True, default='')
    snmp_last_status = models.CharField(max_length=300, blank=True, default='')
    snmp_last_synced_at = models.DateTimeField(blank=True, null=True)
    snmp_down_since = models.DateTimeField(blank=True, null=True)
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
    autofind_onu_count = models.PositiveIntegerField(default=0)
    autofind_new_count = models.PositiveIntegerField(default=0)
    autofind_resync_count = models.PositiveIntegerField(default=0)
    autofind_status = models.CharField(max_length=300, blank=True, default='')
    autofind_refreshed_at = models.DateTimeField(blank=True, null=True)
    dashboard_uptime = models.CharField(max_length=120, blank=True, default='')
    dashboard_temperature = models.CharField(max_length=32, blank=True, default='')
    dashboard_snapshot_refreshed_at = models.DateTimeField(blank=True, null=True)
    attached_vlan_sync_cursor_pk = models.PositiveIntegerField(default=0)
    attached_vlan_sync_status = models.CharField(max_length=300, blank=True, default='')
    attached_vlan_sync_updated_at = models.DateTimeField(blank=True, null=True)
    is_ready = models.BooleanField(default=True, db_index=True)
    onboarding_status = models.CharField(max_length=32, blank=True, default='')
    onboarding_progress = models.PositiveIntegerField(default=0)
    onboarding_message = models.CharField(max_length=255, blank=True, default='')
    onboarding_log = models.TextField(blank=True, default='')
    onboarding_started_at = models.DateTimeField(blank=True, null=True)
    onboarding_finished_at = models.DateTimeField(blank=True, null=True)
    # When False, onboarding fetches only OLT details/cards/PON/uplink/VLAN and
    # skips importing the ONUs (asked at Add OLT time).
    import_onus = models.BooleanField(default=True)
    pricing_mode = models.CharField(max_length=20, choices=PRICING_CHOICES, default=PRICING_STANDARD, db_index=True)
    pricing_expires_at = models.DateTimeField(blank=True, null=True)
    pricing_locked = models.BooleanField(default=False, db_index=True)
    pricing_locked_reason = models.CharField(max_length=255, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    @property
    def pricing_is_expired(self):
        return bool(self.pricing_expires_at and self.pricing_expires_at <= timezone.now())

    @property
    def pricing_access_locked(self):
        return bool(self.pricing_locked or self.pricing_is_expired)

    @property
    def pricing_status_label(self):
        if self.pricing_locked:
            return "Disabled"
        if self.pricing_is_expired:
            return "Expired"
        return "Active"

    @property
    def pricing_lock_message(self):
        if self.pricing_locked:
            return self.pricing_locked_reason or "This OLT is disabled by the service provider."
        if self.pricing_is_expired:
            return "Subscription expired. Please renew your subscription to access this OLT."
        return ""


class SpeedProfile(models.Model):
    index_number = models.PositiveIntegerField(default=0, db_index=True)
    key = models.CharField(max_length=120, unique=True)
    name = models.CharField(max_length=120)
    speed_mbps_value = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    speed_display = models.CharField(max_length=64, blank=True, default='')
    download_name = models.CharField(max_length=160, blank=True, default='')
    upload_name = models.CharField(max_length=160, blank=True, default='')
    download_command = models.TextField(blank=True, default='')
    upload_command = models.TextField(blank=True, default='')
    is_active = models.BooleanField(default=True)
    is_custom = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['speed_mbps_value', 'name']

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
    onu_type_cache = models.CharField(max_length=128, blank=True, default='')
    capability_synced_at = models.DateTimeField(blank=True, null=True)
    attached_vlans_cache = models.CharField(max_length=255, blank=True, default='')
    attached_vlans_synced_at = models.DateTimeField(blank=True, null=True)
    ethernet_port_config_cache = models.TextField(blank=True, default='')
    service_port_id_cache = models.CharField(max_length=255, blank=True, default='')
    user_vlan_cache = models.CharField(max_length=255, blank=True, default='')
    download_profile_index_cache = models.CharField(max_length=255, blank=True, default='')
    upload_profile_index_cache = models.CharField(max_length=255, blank=True, default='')
    download_profile_name_cache = models.CharField(max_length=255, blank=True, default='')
    upload_profile_name_cache = models.CharField(max_length=255, blank=True, default='')
    online_duration_cache = models.CharField(max_length=64, blank=True, default='')
    last_up_time_cache = models.CharField(max_length=64, blank=True, default='')
    last_down_time_cache = models.CharField(max_length=64, blank=True, default='')
    last_down_cause_cache = models.CharField(max_length=128, blank=True, default='')
    battery_state_cache = models.CharField(max_length=64, blank=True, default='')
    onu_mode_cache = models.CharField(max_length=64, blank=True, default='')
    runtime_synced_at = models.DateTimeField(blank=True, null=True)
    onu_rx = models.CharField(max_length=32, blank=True, default='')
    olt_rx = models.CharField(max_length=32, blank=True, default='')
    tx_power = models.CharField(max_length=32, blank=True, default='')
    ont_distance_m = models.CharField(max_length=32, blank=True, default='')
    signal_bucket = models.CharField(max_length=16, blank=True, default='', db_index=True)
    derived_status = models.CharField(max_length=32, blank=True, default='', db_index=True)
    status_source = models.CharField(max_length=32, blank=True, default='')
    status_first_seen_at = models.DateTimeField(blank=True, null=True)
    status_updated_at = models.DateTimeField(blank=True, null=True)
    # True only when this ONU was authorized through OptiVerse. False = imported
    # from the OLT (configured outside the app).
    configured_via_app = models.BooleanField(default=False)
    mapping_mode_cache = models.CharField(max_length=32, blank=True, default='')
    catv_operational_cache = models.CharField(max_length=32, blank=True, default='')
    stability_report_date = models.DateField(blank=True, null=True)
    stability_report_cache = models.JSONField(default=dict, blank=True)
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
    SOURCE_FRESH = 'fresh'
    SOURCE_CARRIED = 'carried'
    SOURCE_SINGLE_RETRY = 'single_retry'
    SOURCE_STALE = 'stale'
    SAMPLE_SOURCE_CHOICES = [
        (SOURCE_FRESH, 'Fresh'),
        (SOURCE_CARRIED, 'Carried'),
        (SOURCE_SINGLE_RETRY, 'Single retry'),
        (SOURCE_STALE, 'Stale'),
    ]

    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='onu_optical_samples')
    slot = models.PositiveIntegerField()
    port = models.PositiveIntegerField()
    ont_id = models.PositiveIntegerField()
    onu_rx = models.CharField(max_length=32, blank=True, default='')
    olt_rx = models.CharField(max_length=32, blank=True, default='')
    tx_power = models.CharField(max_length=32, blank=True, default='')
    sample_source = models.CharField(max_length=16, choices=SAMPLE_SOURCE_CHOICES, default=SOURCE_FRESH, db_index=True)
    sampled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sampled_at']
        indexes = [
            models.Index(fields=['olt', 'slot', 'port', 'ont_id', 'sampled_at'], name='onu_sample_lookup_idx'),
            models.Index(fields=['sampled_at'], name='onu_opt_time_idx'),
        ]

    def __str__(self):
        return f"{self.olt.name} {self.slot}/{self.port}:{self.ont_id} @ {self.sampled_at}"


class ONUStatusSample(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='onu_status_samples')
    slot = models.PositiveIntegerField()
    port = models.PositiveIntegerField()
    ont_id = models.PositiveIntegerField()
    status = models.CharField(max_length=32, db_index=True)
    source = models.CharField(max_length=32, blank=True, default='')
    sampled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sampled_at']
        indexes = [
            models.Index(fields=['olt', 'slot', 'port', 'ont_id', 'sampled_at'], name='onu_status_lookup_idx'),
            models.Index(fields=['sampled_at'], name='onu_status_time_idx'),
        ]

    def __str__(self):
        return f"{self.olt.name} {self.slot}/{self.port}:{self.ont_id} {self.status} @ {self.sampled_at}"


class ONUTrafficSample(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='onu_traffic_samples')
    slot = models.PositiveIntegerField()
    port = models.PositiveIntegerField()
    ont_id = models.PositiveIntegerField()
    up_bytes = models.BigIntegerField(default=0)
    down_bytes = models.BigIntegerField(default=0)
    up_packets = models.BigIntegerField(default=0)
    down_packets = models.BigIntegerField(default=0)
    up_bps = models.FloatField(default=0)
    down_bps = models.FloatField(default=0)
    sampled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sampled_at']
        indexes = [
            models.Index(fields=['olt', 'slot', 'port', 'ont_id', 'sampled_at'], name='onu_traffic_lookup_idx'),
            models.Index(fields=['sampled_at'], name='onu_traf_time_idx'),
        ]

    def __str__(self):
        return f"{self.olt.name} {self.slot}/{self.port}:{self.ont_id} traffic @ {self.sampled_at}"


class DashboardStatusSample(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='dashboard_status_samples', null=True, blank=True)
    total_onus = models.PositiveIntegerField(default=0)
    online_onus = models.PositiveIntegerField(default=0)
    offline_onus = models.PositiveIntegerField(default=0)
    wait_for_authorize_total = models.PositiveIntegerField(default=0)
    wait_for_authorize_new_total = models.PositiveIntegerField(default=0)
    wait_for_authorize_resync_total = models.PositiveIntegerField(default=0)
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


class PONTrafficSample(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='pon_traffic_samples', null=True, blank=True)
    in_octets = models.BigIntegerField(default=0)
    out_octets = models.BigIntegerField(default=0)
    in_packets = models.BigIntegerField(default=0)
    out_packets = models.BigIntegerField(default=0)
    sampled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sampled_at']
        indexes = [
            models.Index(fields=['olt', 'sampled_at'], name='pon_traffic_olt_time_idx'),
            models.Index(fields=['sampled_at'], name='pon_traffic_time_idx'),
        ]

    def __str__(self):
        scope = self.olt.name if self.olt_id else 'All OLTs'
        return f"{scope} PON traffic @ {self.sampled_at}"


class PONPortTrafficSample(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='pon_port_traffic_samples')
    slot = models.PositiveIntegerField(default=0)
    port = models.PositiveIntegerField(default=0)
    in_octets = models.BigIntegerField(default=0)
    out_octets = models.BigIntegerField(default=0)
    in_packets = models.BigIntegerField(default=0)
    out_packets = models.BigIntegerField(default=0)
    sampled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sampled_at']
        indexes = [
            models.Index(fields=['olt', 'slot', 'port', 'sampled_at'], name='pon_port_slot_time_idx'),
            models.Index(fields=['olt', 'sampled_at'], name='pon_port_olt_time_idx'),
            models.Index(fields=['sampled_at'], name='pon_port_time_idx'),
        ]

    def __str__(self):
        return f"{self.olt.name} GPON 0/{self.slot}/{self.port} @ {self.sampled_at}"


class UplinkPortTrafficSample(models.Model):
    olt = models.ForeignKey(OLT, on_delete=models.CASCADE, related_name='uplink_port_traffic_samples')
    port_name = models.CharField(max_length=64)
    in_octets = models.BigIntegerField(default=0)
    out_octets = models.BigIntegerField(default=0)
    sampled_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['sampled_at']
        indexes = [
            models.Index(fields=['olt', 'port_name', 'sampled_at'], name='uplk_port_time_idx'),
            models.Index(fields=['olt', 'sampled_at'], name='uplk_olt_time_idx'),
            models.Index(fields=['sampled_at'], name='uplk_time_idx'),
        ]

    def __str__(self):
        return f"{self.olt.name} {self.port_name} @ {self.sampled_at}"


class AlertConfig(models.Model):
    """Singleton (pk=1) holding alert + email notification settings."""
    email_enabled = models.BooleanField(default=False)
    email_recipients = models.TextField(blank=True, default='', help_text='Comma / newline separated email addresses')
    notify_olt_down = models.BooleanField(default=True)
    notify_olt_recovered = models.BooleanField(default=True)
    notify_high_temp = models.BooleanField(default=True)
    # Fiber-cut / mass-outage detection: many ONUs on one PON port down together.
    notify_fiber_cut = models.BooleanField(default=True)
    fiber_cut_min_onus = models.PositiveIntegerField(default=4)
    fiber_cut_ratio = models.PositiveIntegerField(default=60)  # percent down on a port
    # Signal degradation early-warning: ONU Rx power steadily dropping toward the cliff.
    notify_signal_degrade = models.BooleanField(default=True)
    signal_degrade_drop_db = models.PositiveIntegerField(default=3)  # dB drop over window
    temp_threshold_c = models.PositiveIntegerField(default=60)
    renotify_minutes = models.PositiveIntegerField(default=30)
    # SMTP — configured here so no env vars / server restart are needed.
    smtp_host = models.CharField(max_length=120, blank=True, default='')
    smtp_port = models.PositiveIntegerField(default=587)
    smtp_use_tls = models.BooleanField(default=True)
    smtp_username = models.CharField(max_length=200, blank=True, default='')
    smtp_password = models.CharField(max_length=200, blank=True, default='')
    smtp_from = models.CharField(max_length=200, blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return 'Alert configuration'

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def recipient_list(self):
        parts = re.split(r'[,\n;]+', str(self.email_recipients or ''))
        seen = []
        for part in parts:
            value = part.strip()
            if value and value not in seen:
                seen.append(value)
        return seen


class AlertEvent(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('warning', 'Warning'),
        ('info', 'Info'),
    ]
    alert_type = models.CharField(max_length=40, db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='warning')
    olt = models.ForeignKey(OLT, on_delete=models.SET_NULL, null=True, blank=True, related_name='alert_events')
    dedup_key = models.CharField(max_length=160, db_index=True)
    title = models.CharField(max_length=200)
    message = models.TextField(blank=True, default='')
    details = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)
    email_sent_at = models.DateTimeField(null=True, blank=True)
    last_notified_at = models.DateTimeField(null=True, blank=True)
    notify_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['is_active', 'dedup_key'], name='alert_active_key_idx'),
            models.Index(fields=['is_active', 'created_at'], name='alert_active_time_idx'),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.title}"
