# SOC Flow: Wazuh + VirusTotal + n8n

This repository demonstrates a Security Operations Center (SOC) workflow integrating **Wazuh**, **VirusTotal**, and **n8n** for automated detection, alerting, and response.

---

## 🚀 Features

- **Wazuh Integration**
  - Configure multiple rule groups (e.g., FIM, Sysmon, MariaDB audit).
  - Send alerts via webhooks to `n8n` using HTTP POST.
  - JSON-based alert forwarding.

- **n8n Workflow**
  - Parse Wazuh alerts and extract key metadata (MD5, SHA1, SHA256, file path, rule description, agent, level).
  - Automate file hash lookups in **VirusTotal**.
  - Generate alerts in multiple formats (HTML, Gmail, Discord).

- **VirusTotal Integration**
  - Automatic scanning and enrichment of file hashes.
  - Provides classification of malicious, suspicious, or harmless files.

---

## ⚙️ Setup Instructions

### 1. Configure Wazuh Manager
Edit `/var/ossec/etc/ossec.conf` and add custom webhook integrations:

```xml
<integration>
  <name>custom-n8n</name>
  <hook_url>https://your-ngrok-url/webhook-windows</hook_url>
  <rule_id>550,554</rule_id> <!-- Sysmon process injection rules -->
  <alert_format>json</alert_format>
</integration>

<integration>
  <name>custom-n8n</name>
  <hook_url>https://your-ngrok-url/webhook-db</hook_url>
  <rule_id>554</rule_id> <!-- MariaDB audit rules -->
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh Manager:
```bash
systemctl restart wazuh-manager
```

Verify integration:
```bash
tail -f /var/ossec/log/integration.log
```

### 2. Configure Agent Endpoints
Add FIM rules in `/var/ossec/etc/ossec.conf` for directories such as:
```
/root, /home, /home/download
```

Test by downloading files (e.g., **EICAR.COM**) in monitored paths.

### 3. Configure n8n Workflow
Add a **Code Node** to parse Wazuh alerts:

```javascript
const body = items[0].json.body || {};
const allFields = body.all_fields || {};
const syscheck = allFields.syscheck || {};
const rule = allFields.rule || {};

return [{
  json: {
    type: 'file_alert',
    md5: syscheck.md5_after || null,
    sha1: syscheck.sha1_after || null,
    sha256: syscheck.sha256_after || null,
    file_path: syscheck.path || null,
    description: rule.description || 'No description',
    agent: allFields.agent?.name || 'unknown',
    level: rule.level || 'unknown',
    full_alert: body
  }
}];
```

This captures **file hashes** and metadata for VirusTotal queries.

### 4. VirusTotal Integration
- Connect extracted hashes to VirusTotal API.
- Fetch reputation results for automation.

### 5. Notifications
- Generate HTML reports.
- Configure **Gmail** for email alerts.
- Configure **Discord** webhook for real-time notifications.

---

## 🧪 Example Workflow
1. Wazuh detects suspicious file activity.
2. Alert sent to `n8n` webhook.
3. n8n extracts file hashes → queries VirusTotal.
4. Results enriched and forwarded to:
   - Gmail inbox (HTML report).
   - Discord channel (JSON/alert format).

---

## 📂 Project Structure
```
/wazuh-config       → Wazuh integration XML configs
/n8n-workflow       → n8n JSON export files
/html-templates     → HTML templates for alerts
/docs               → Documentation and setup guides
```

---

## 🔒 Security Considerations
- Ensure `ngrok` or public webhook endpoints are properly secured.
- Restrict API keys (VirusTotal, Gmail) to minimal required scopes.
- Monitor `/var/ossec/log/integration.log` for errors.

---

## 📜 License
This project is licensed under the MIT License.

---

## 🤝 Contributing
Feel free to fork this repository, submit issues, and open pull requests to improve automation and detection workflows.

---

## 👤 Author
Developed as part of SOC automation workflow research using **Wazuh**, **VirusTotal**, and **n8n**.
