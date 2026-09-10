from pathlib import Path
from datetime import datetime

log_file = Path("logs/auth.log")
report_file = Path("reports/security_report.txt")

successful_logins = 0
failed_logins = 0

failed_attempts_by_ip = {}
failed_attempts_by_user = {}
failed_attempts_by_ip_user = {}
failed_attempt_times = {}

print("Security Log Analyzer")
print("=====================")
print()

# Read and analyze the log file
with log_file.open("r") as file:
    for line in file:
        line = line.strip()

        if "Login successful" in line:
            successful_logins += 1

        elif "Failed login" in line:
            failed_logins += 1

            parts = line.split()

            # Extract timestamp
            timestamp = datetime.strptime(
                f"{parts[0]} {parts[1]}",
                "%Y-%m-%d %H:%M:%S"
            )

            # Extract username and IP address
            username = parts[-2].split("=")[1]
            ip_address = parts[-1].split("=")[1]

            # Count failed attempts by IP
            if ip_address in failed_attempts_by_ip:
                failed_attempts_by_ip[ip_address] += 1
            else:
                failed_attempts_by_ip[ip_address] = 1

            # Count failed attempts by username
            if username in failed_attempts_by_user:
                failed_attempts_by_user[username] += 1
            else:
                failed_attempts_by_user[username] = 1

            # Count failed attempts by IP and username
            key = (ip_address, username)

            if key in failed_attempts_by_ip_user:
                failed_attempts_by_ip_user[key] += 1
            else:
                failed_attempts_by_ip_user[key] = 1

            # Store timestamps for each IP
            if ip_address in failed_attempt_times:
                failed_attempt_times[ip_address].append(timestamp)
            else:
                failed_attempt_times[ip_address] = [timestamp]


# Display results in terminal
print(f"Successful logins: {successful_logins}")
print(f"Failed logins: {failed_logins}")
print()

print("Failed Attempts by IP")
print("---------------------")

for ip_address, attempts in failed_attempts_by_ip.items():
    print(f"{ip_address}: {attempts}")

print()

print("Failed Attempts by Username")
print("---------------------------")

for username, attempts in failed_attempts_by_user.items():
    print(f"{username}: {attempts}")

print()

print("Suspicious Activity")
print("-------------------")

for (ip_address, username), attempts in failed_attempts_by_ip_user.items():

    if attempts >= 3:

        timestamps = failed_attempt_times[ip_address]

        first_attempt = min(timestamps)
        last_attempt = max(timestamps)

        duration = last_attempt - first_attempt

        if duration.total_seconds() <= 30:
            attack_type = "Rapid Login Attack"
            severity = "HIGH"
        else:
            attack_type = "Repeated Failed Login"
            severity = "MEDIUM"

        print("ALERT")
        print(f"IP Address: {ip_address}")
        print(f"Target Account: {username}")
        print(f"Failed Attempts: {attempts}")
        print(f"First Attempt: {first_attempt}")
        print(f"Last Attempt: {last_attempt}")
        print(f"Attack Duration: {duration}")
        print(f"Attack Type: {attack_type}")
        print(f"Severity: {severity}")
        print()


# Generate security report
print("Generating security report...")

with report_file.open("w") as report:

    report.write("SECURITY LOG ANALYSIS REPORT\n")
    report.write("============================\n\n")

    # Login summary
    report.write("LOGIN SUMMARY\n")
    report.write("-------------\n")
    report.write(f"Successful logins: {successful_logins}\n")
    report.write(f"Failed logins: {failed_logins}\n\n")

    # Incident summary
    report.write("INCIDENT SUMMARY\n")
    report.write("----------------\n")
    report.write(
        "Multiple failed login attempts were detected against "
        "user accounts.\n"
    )
    report.write(
        "Some attempts occurred rapidly and exceeded the configured "
        "detection threshold.\n"
    )
    report.write(
        "The activity may indicate a brute-force or password-guessing "
        "attempt.\n"
    )
    report.write(
        "Further investigation is recommended to determine whether "
        "any account was compromised.\n\n"
    )

    # Failed attempts by IP
    report.write("FAILED ATTEMPTS BY IP\n")
    report.write("---------------------\n")

    for ip_address, attempts in failed_attempts_by_ip.items():
        report.write(f"{ip_address}: {attempts}\n")

    report.write("\n")

    # Failed attempts by username
    report.write("FAILED ATTEMPTS BY USERNAME\n")
    report.write("---------------------------\n")

    for username, attempts in failed_attempts_by_user.items():
        report.write(f"{username}: {attempts}\n")

    report.write("\n")

    # Suspicious activity
    report.write("SUSPICIOUS ACTIVITY\n")
    report.write("-------------------\n")

    for (ip_address, username), attempts in failed_attempts_by_ip_user.items():

        if attempts >= 3:

            timestamps = failed_attempt_times[ip_address]

            first_attempt = min(timestamps)
            last_attempt = max(timestamps)

            duration = last_attempt - first_attempt

            if duration.total_seconds() <= 30:
                attack_type = "Rapid Login Attack"
                severity = "HIGH"
            else:
                attack_type = "Repeated Failed Login"
                severity = "MEDIUM"

            report.write("ALERT\n")
            report.write(f"IP Address: {ip_address}\n")
            report.write(f"Target Account: {username}\n")
            report.write(f"Failed Attempts: {attempts}\n")
            report.write(f"First Attempt: {first_attempt}\n")
            report.write(f"Last Attempt: {last_attempt}\n")
            report.write(f"Attack Duration: {duration}\n")
            report.write(f"Attack Type: {attack_type}\n")
            report.write(f"Severity: {severity}\n")

            # Recommended actions
            report.write("RECOMMENDED ACTION\n")
            report.write("------------------\n")
            report.write(
                "- Investigate the source IP address.\n"
            )
            report.write(
                "- Review authentication logs for additional activity.\n"
            )
            report.write(
                "- Verify whether the targeted account was compromised.\n"
            )
            report.write(
                "- Consider blocking the source IP if the activity "
                "is confirmed malicious.\n"
            )
            report.write("\n")


print(f"Security report generated: {report_file}")
