import json
from datetime import datetime, timedelta
from attack_detector import AttackDetector

# ------------------ JSON LOGGING ------------------

flagged_events = []

def log_event(test_name, **event_details):
    event = {"test": test_name, **event_details}
    flagged_events.append(event)

def save_flagged_events_to_json(filename="flagged_events.json"):
    with open(filename, "w") as f:
        json.dump(flagged_events, f, indent=2)

# ------------------ UNIT TESTS ------------------

def test_login_spam_detection():
    print("\n[Unit Test] Login spam detection")

    detector = AttackDetector()
    base_time = datetime.utcnow().replace(hour=11, minute=0, second=0, microsecond=0)

    # Case 1: Normal user - 5 failed attempts within 1 min (should NOT flag)
    for i in range(5):
        flagged, reason = detector.detect_login_spam(
            user_id="user_1",
            user_role="USER",
            timestamp=base_time + timedelta(seconds=i * 5),
            context={"success": False}
        )
    print(f"USER with 5 failed attempts: flagged={flagged}, reason='{reason}'")

    # Case 2: Normal user - 6th failed attempt within 1 min (should flag)
    timestamp = base_time + timedelta(seconds=25)
    flagged, reason = detector.detect_login_spam(
        user_id="user_1",
        user_role="USER",
        timestamp=timestamp,
        context={"success": False}
    )
    if flagged:
        log_event("test_login_spam_detection", user_id="user_1", user_role="USER",
                  timestamp=timestamp.isoformat(), reason=reason, context={"success": False})
    print(f"USER 6th failed attempt: flagged={flagged}, reason='{reason}'")

    # Case 3: ADMIN with failed logins during business hours with active session (should be whitelisted)
    for i in range(6):
        flagged, reason = detector.detect_login_spam(
            user_id="admin_1",
            user_role="ADMIN",
            timestamp=base_time + timedelta(seconds=i * 5),
            context={"success": False, "active_session": True}
        )
    print(f"ADMIN with failed attempts (whitelisted): flagged={flagged}, reason='{reason}'")

    # Case 4: Successful login attempts should not be counted
    for i in range(6):
        flagged, reason = detector.detect_login_spam(
            user_id="user_2",
            user_role="USER",
            timestamp=base_time + timedelta(seconds=i * 5),
            context={"success": True}
        )
    print(f"USER with successful logins: flagged={flagged}, reason='{reason}'")

def test_toggle_spam_detection():
    print("\n[Unit Test] Toggle spam detection")

    detector = AttackDetector()
    now = datetime.utcnow().replace(hour=10, minute=0, second=0, microsecond=0)

    # Authorized toggle burst (ADMIN during business hours with active session)
    for i in range(12):
        flagged, reason = detector.detect_toggle_spam(
            user_id="admin123",
            user_role="ADMIN",
            timestamp=now + timedelta(seconds=i),
            context={"active_session": True}
        )
    print(f"Trusted ADMIN burst: flagged={flagged}, reason='{reason}'")

    # Unauthorized toggle burst (USER without session)
    for i in range(12):
        ts = now + timedelta(seconds=i)
        flagged, reason = detector.detect_toggle_spam(
            user_id="user456",
            user_role="USER",
            timestamp=ts,
            context={"active_session": False}
        )
        if i == 11 and flagged:
            log_event("test_toggle_spam_detection", user_id="user456", user_role="USER",
                      timestamp=ts.isoformat(), reason=reason, context={"active_session": False})
            print(f"Untrusted USER burst: flagged={flagged}, reason='{reason}'")

def test_anomaly_detection():
    print("\n[Unit Test] Sensor anomaly detection")
    detector = AttackDetector()
    now = datetime.utcnow().replace(microsecond=0)

    # Populate history with normal readings
    for i in range(10):
        detector.detect_anomalies(
            sensor_id="sensorX",
            value=100 + i,
            timestamp=now + timedelta(seconds=i),
            allow_zero=False
        )

    # Send a valid reading (should NOT flag)
    flagged, reason = detector.detect_anomalies(
        sensor_id="sensorX",
        value=120,
        timestamp=now,
        allow_zero=False
    )
    print(f"Test normal value: flagged={flagged}, reason='{reason}'")

    # Send a spike (should flag)
    flagged, reason = detector.detect_anomalies(
        sensor_id="sensorX",
        value=200,
        timestamp=now,
        allow_zero=False
    )
    if flagged:
        log_event("test_anomaly_detection", sensor_id="sensorX", timestamp=now.isoformat(),
                  reason=reason, value=200)
    print(f"Test power spike: flagged={flagged}, reason='{reason}'")

    # Test negative value (should flag)
    flagged, reason = detector.detect_anomalies(
        sensor_id="sensorX",
        value=-10,
        timestamp=now,
        allow_zero=False
    )
    if flagged:
        log_event("test_anomaly_detection", sensor_id="sensorX", timestamp=now.isoformat(),
                  reason=reason, value=-10)
    print(f"Test negative value: flagged={flagged}, reason='{reason}'")

    # Test unexpected zero (should flag)
    flagged, reason = detector.detect_anomalies(
        sensor_id="sensorX",
        value=0,
        timestamp=now,
        allow_zero=False
    )
    if flagged:
        log_event("test_anomaly_detection", sensor_id="sensorX", timestamp=now.isoformat(),
                  reason=reason, value=0)
    print(f"Test zero (not allowed): flagged={flagged}, reason='{reason}'")

def test_unknown_device_login_spam():
    print("\n[Unit Test] Unknown device login spam detection (DDoS detection)")
    detector = AttackDetector()
    now = datetime.utcnow().replace(hour=9, minute=0, second=0, microsecond=0)

    # Case 1: 20 unique unknown devices (should NOT flag)
    for i in range(20):
        device_id = f"device_{i}"
        flagged, reason = detector.detect_unknown_device_login_spam(
            device_id=device_id,
            timestamp=now + timedelta(seconds=i % 30)
        )
    print(f"20 unique unknown devices: flagged={flagged}, reason='{reason}'")

    # Case 2: 11th unique unknown device within 60s window (should flag)
    ts = now + timedelta(seconds=55)
    flagged, reason = detector.detect_unknown_device_login_spam(
        device_id="device_11",
        timestamp=ts
    )
    if flagged:
        log_event("test_unknown_device_login_spam", device_id="device_11", timestamp=ts.isoformat(), reason=reason)
    print(f"11th unique unknown device: flagged={flagged}, reason='{reason}'")

    # Case 3: Known device should not be flagged
    known_device_id = "device_known"
    detector.known_devices.add(known_device_id)
    flagged, reason = detector.detect_unknown_device_login_spam(
        device_id=known_device_id,
        timestamp=now + timedelta(seconds=58)
    )
    print(f"Known device attempt: flagged={flagged}, reason='{reason}'")

def test_multiple_ip_logins():
    print("\n[Unit Test] Multiple IP logins by same user in short time window")

    detector = AttackDetector()
    base_time = datetime.utcnow().replace(hour=13, minute=0, second=0, microsecond=0)

    user_id = "user_shared"

    # Case 1: Login from same IP repeatedly (should NOT flag)
    for i in range(3):
        flagged, reason = detector.detect_multiple_ip_logins(
            user_id=user_id,
            ip_address="192.168.1.1",
            timestamp=base_time + timedelta(seconds=i * 10)
        )
    print(f"Same IP logins: flagged={flagged}, reason='{reason}'")

    # Case 2: 3 different IPs within 60s (should flag)
    ip_list = ["10.0.0.1", "172.16.0.5", "8.8.8.8"]
    for i, ip in enumerate(ip_list):
        ts = base_time + timedelta(seconds=i * 15)
        flagged, reason = detector.detect_multiple_ip_logins(
            user_id=user_id,
            ip_address=ip,
            timestamp=ts
        )
        if i == len(ip_list) - 1 and flagged:
            log_event("test_multiple_ip_logins", user_id=user_id, timestamp=ts.isoformat(),
                      ip_addresses=ip_list, reason=reason)
            print(f"Multiple IPs in 60s: flagged={flagged}, reason='{reason}'")

# ------------------ MAIN ------------------

if __name__ == "__main__":
    test_login_spam_detection()
    test_toggle_spam_detection()
    test_anomaly_detection()
    test_unknown_device_login_spam()
    test_multiple_ip_logins()
    save_flagged_events_to_json()
