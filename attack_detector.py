from collections import defaultdict
from datetime import datetime
from collections import deque

class AttackDetector:
    def __init__(self):
        self.login_attempts = defaultdict(list)
        self.toggle_events = defaultdict(list)
        self.sensor_history = defaultdict(list)
        self.known_devices = set()
        self.unknown_device_attempts = defaultdict(list)
        self.recent_unknown_device_attempts = deque()
        self.user_ip_history = defaultdict(list)


    def in_business_hours(self, timestamp: datetime):
        return 8 <= timestamp.hour < 18

    def is_authorized_context(self, user_role, context, timestamp):
        active_session = context.get("active_session", False)
        privileged = context.get("privileged_command", False)

        if user_role in {"ADMIN", "MANAGER"} and self.in_business_hours(timestamp) and active_session:
            return True

        if privileged:
            return True

        return False

    def detect_login_spam(self, user_id, user_role, timestamp, context):
        if self.is_authorized_context(user_role, context, timestamp):
            return False, "Whitelisted due to trusted context"

        if not context.get("success", True):
            self.login_attempts[user_id].append(timestamp)
            recent = [t for t in self.login_attempts[user_id] if (timestamp - t).total_seconds() <= 60]
            self.login_attempts[user_id] = recent
            if len(recent) > 5:
                return True, "Too many failed login attempts in 1 minute"

        return False, "none"

    def detect_toggle_spam(self, user_id, user_role, timestamp, context):
        if self.is_authorized_context(user_role, context, timestamp):
            return False, "Whitelisted due to trusted context"

        self.toggle_events[user_id].append(timestamp)
        recent = [t for t in self.toggle_events[user_id] if (timestamp - t).total_seconds() <= 30]
        self.toggle_events[user_id] = recent
        if len(recent) > 10:
            return True, "Toggle spam: >10 toggle events in 30 seconds"

        return False, "none"

    def detect_anomalies(self, sensor_id, value, timestamp, allow_zero=False):
        flagged = False
        reason = None

        if value < 0 or (value == 0 and not allow_zero):
            return True, "Invalid sensor value: negative or unexpected zero"

        history = self.sensor_history[sensor_id]
        if history:
            avg = sum(history) / len(history)
            if value > 1.5 * avg:
                flagged = True
                reason = f"Spike detected: {value:.2f} > 150% of avg {avg:.2f}"

        self.sensor_history[sensor_id].append(value)
        return flagged, reason or "none"

    def detect_unknown_device_login_spam(self, device_id, timestamp):
        """
        Detects distributed login attempts from unknown devices (>50 unique unknown devices in 60 seconds).
        """
        if device_id in self.known_devices:
            return False, "Known device"

        # Track all unknown device login attempts
        self.unknown_device_attempts[device_id].append(timestamp)
        self.recent_unknown_device_attempts.append((timestamp, device_id))

        # Purge old entries from deque (older than 60 seconds)
        while self.recent_unknown_device_attempts and \
              (timestamp - self.recent_unknown_device_attempts[0][0]).total_seconds() > 60:
            self.recent_unknown_device_attempts.popleft()

        # Count unique unknown devices in the last 60 seconds
        unique_devices = set(dev_id for _, dev_id in self.recent_unknown_device_attempts)
        if len(unique_devices) > 10:
            return True, f"DDoS suspected: {len(unique_devices)} unknown devices attempted login in last 60s"

        return False, "none"

    def detect_multiple_ip_logins(self, user_id, ip_address, timestamp):
        """
        Detects if the same user logs in from different IPs within 60 seconds.
        """
        self.user_ip_history[user_id].append((timestamp, ip_address))

        # Keep only logins within the last 60 seconds
        recent = [
            (t, ip) for (t, ip) in self.user_ip_history[user_id]
            if (timestamp - t).total_seconds() <= 60
        ]
        self.user_ip_history[user_id] = recent

        # Count unique IP addresses in the last 60 seconds
        unique_ips = set(ip for _, ip in recent)

        if len(unique_ips) > 2:  # Allow small variation (like dynamic IP changes), flag only if >2 IPs
            return True, f"Multiple IPs used by user {user_id} in 60s: {list(unique_ips)}"

        return False, "none"
    


