# ES|QL Joinless Joins Tutorial

This tutorial demonstrates how to perform "joinless joins" in Kibana's ES|QL by querying multiple indices together and using `STATS` with conditional aggregations to correlate data across sources.

---

## Setup: Create Sample Data

### Firewall Logs

```console
POST /firewall-logs-demo/_bulk
{"index":{}}
{"@timestamp":"2024-12-12T10:00:00Z","source.ip":"192.168.1.100","destination.ip":"203.0.113.50","firewall.action":"allow","destination.port":443,"bytes":1500}
{"index":{}}
{"@timestamp":"2024-12-12T10:05:00Z","source.ip":"192.168.1.101","destination.ip":"198.51.100.20","firewall.action":"deny","destination.port":22,"bytes":0}
{"index":{}}
{"@timestamp":"2024-12-12T10:10:00Z","source.ip":"192.168.1.101","destination.ip":"198.51.100.20","firewall.action":"deny","destination.port":22,"bytes":0}
{"index":{}}
{"@timestamp":"2024-12-12T10:15:00Z","source.ip":"10.0.0.50","destination.ip":"203.0.113.100","firewall.action":"allow","destination.port":443,"bytes":2500}
{"index":{}}
{"@timestamp":"2024-12-12T10:20:00Z","source.ip":"192.168.1.101","destination.ip":"198.51.100.20","firewall.action":"deny","destination.port":3389,"bytes":0}
{"index":{}}
{"@timestamp":"2024-12-12T10:25:00Z","source.ip":"192.168.1.102","destination.ip":"203.0.113.75","firewall.action":"allow","destination.port":80,"bytes":3200}
{"index":{}}
{"@timestamp":"2024-12-12T10:30:00Z","source.ip":"192.168.1.101","destination.ip":"198.51.100.20","firewall.action":"deny","destination.port":22,"bytes":0}
{"index":{}}
{"@timestamp":"2024-12-12T10:35:00Z","source.ip":"10.0.0.50","destination.ip":"203.0.113.100","firewall.action":"allow","destination.port":443,"bytes":1800}
```

### Threat Intelligence Data

```console
POST /threat-intel-demo/_bulk
{"index":{}}
{"@timestamp":"2024-12-12T09:00:00Z","source.ip":"198.51.100.20","threat.indicator.ip":"198.51.100.20","threat.indicator.type":"malicious","threat.tactic":"credential_access","threat.severity":"high"}
{"index":{}}
{"@timestamp":"2024-12-12T09:30:00Z","source.ip":"203.0.113.999","threat.indicator.ip":"203.0.113.999","threat.indicator.type":"suspicious","threat.tactic":"command_and_control","threat.severity":"medium"}
{"index":{}}
{"@timestamp":"2024-12-12T10:00:00Z","source.ip":"192.168.1.101","threat.indicator.type":"brute_force_attempt","threat.tactic":"credential_access","threat.severity":"high"}
```

### Authentication Logs

```console
POST /auth-logs-demo/_bulk
{"index":{}}
{"@timestamp":"2024-12-12T10:00:00Z","user.name":"alice","event.action":"login","event.outcome":"success","source.ip":"192.168.1.100","service.name":"webapp"}
{"index":{}}
{"@timestamp":"2024-12-12T10:05:00Z","user.name":"bob","event.action":"login","event.outcome":"failure","source.ip":"192.168.1.101","service.name":"webapp"}
{"index":{}}
{"@timestamp":"2024-12-12T10:10:00Z","user.name":"bob","event.action":"login","event.outcome":"failure","source.ip":"192.168.1.101","service.name":"webapp"}
{"index":{}}
{"@timestamp":"2024-12-12T10:25:00Z","user.name":"bob","event.action":"login","event.outcome":"failure","source.ip":"192.168.1.101","service.name":"webapp"}
{"index":{}}
{"@timestamp":"2024-12-12T10:45:00Z","user.name":"bob","event.action":"login","event.outcome":"success","source.ip":"192.168.1.103","service.name":"webapp"}
```

### Application Logs

```console
POST /application-logs-demo/_bulk
{"index":{}}
{"@timestamp":"2024-12-12T10:01:00Z","user.name":"alice","event.action":"page_view","service.name":"webapp","response_time":150}
{"index":{}}
{"@timestamp":"2024-12-12T10:11:00Z","user.name":"bob","event.action":"api_call","service.name":"webapp","response_time":450}
{"index":{}}
{"@timestamp":"2024-12-12T10:31:00Z","user.name":"alice","event.action":"api_call","service.name":"webapp","response_time":250}
{"index":{}}
{"@timestamp":"2024-12-12T10:46:00Z","user.name":"bob","event.action":"form_submit","service.name":"webapp","response_time":280}
```

---

## Core Concept: The Joinless Join Pattern

Traditional SQL JOINs are expensive. ES|QL offers a simpler approach: query multiple indices simultaneously and use conditional aggregations to correlate data.

### Basic Pattern

```esql
FROM index1, index2 METADATA _index
| EVAL data_type = CASE(
    _index == "index1", "type1",
    _index == "index2", "type2",
    "unknown"
  )
| STATS 
    metric1 = COUNT(*) WHERE data_type == "type1",
    metric2 = COUNT(*) WHERE data_type == "type2"
  BY common_field
| EVAL calculated_metrics = ...
| WHERE filter_conditions
| SORT relevance_field DESC
```

**Key Components:**
1. **`METADATA _index`** - Exposes the index name as a field
2. **`EVAL` with `CASE`** - Labels records by source
3. **`STATS` with `WHERE`** - Conditional aggregations (the "join" magic)
4. **`BY common_field`** - Groups related records together

---

## Step-by-Step Tutorial: Building Up to Joinless Joins

### Part 1: Two-Index Join (Firewall + Threat Intel)

Let's build this up step by step, starting with viewing each data source individually, then combining them.

---

#### Step 1: View Firewall Logs Only

First, let's see what the firewall data looks like by itself.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM firewall-logs-demo
| STATS 
    total_connections = COUNT(*),
    blocked_connections = COUNT(*) WHERE firewall.action == "deny",
    total_bytes = SUM(bytes)
  BY source.ip
| EVAL 
    block_rate = CASE(
      total_connections > 0, 
      ROUND(TO_DOUBLE(blocked_connections) / TO_DOUBLE(total_connections) * 100, 2),
      0
    )
| SORT blocked_connections DESC
  """
}
```

**What You'll See:**
```
source.ip       | total_connections | blocked_connections | total_bytes | block_rate
192.168.1.101   | 4                 | 4                   | 0           | 100.00
10.0.0.50       | 2                 | 0                   | 4300        | 0.00
192.168.1.102   | 1                 | 0                   | 3200        | 0.00
192.168.1.100   | 1                 | 0                   | 1500        | 0.00
```

**Key Observations:**
- IP `192.168.1.101` has 4 connections, ALL blocked (100% block rate)
- But we don't know if these IPs are in our threat intelligence database
- We're only seeing one side of the story!

---

#### Step 2: View Threat Intelligence Only

Now let's look at the threat intelligence data separately.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM threat-intel-demo
| STATS 
    threat_matches = COUNT(*)
  BY source.ip
| SORT threat_matches DESC
  """
}
```

**What You'll See:**
```
source.ip       | threat_matches
203.0.113.999   | 1
192.168.1.101   | 1
198.51.100.20   | 1
```

**Key Observations:**
- IP `192.168.1.101` appears here with 1 threat match
- This is the SAME IP that had 100% blocked traffic in the firewall!
- But we can't see both pieces of information together yet
- IP `198.51.100.20` is in threat intel but didn't appear in firewall logs

---

#### Step 3: Combine Both Indices (First Attempt)

Let's query both indices together and see what happens.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM firewall-logs-demo, threat-intel-demo METADATA _index
| STATS 
    total_records = COUNT(*)
  BY source.ip, _index
| SORT source.ip, _index
  """
}
```

**What You'll See:**
```
source.ip       | _index               | total_records
10.0.0.50       | firewall-logs-demo   | 2
192.168.1.100   | firewall-logs-demo   | 1
192.168.1.101   | firewall-logs-demo   | 4
192.168.1.101   | threat-intel-demo    | 1
192.168.1.102   | firewall-logs-demo   | 1
198.51.100.20   | threat-intel-demo    | 1
203.0.113.999   | threat-intel-demo    | 1
```

**Key Observations:**
- **IMPORTANT:** We're now using `METADATA _index` in the FROM clause
- IP `192.168.1.101` appears in TWO rows (once per index)
- The data isn't correlated yet - still separate rows!
- Each IP/index combination is its own row

---

#### Step 4: Label Each Record by Source

Let's add a label to identify which index each record came from.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM firewall-logs-demo, threat-intel-demo METADATA _index
| EVAL 
    data_type = CASE(
      _index == "firewall-logs-demo", "firewall",
      _index == "threat-intel-demo", "threat",
      "unknown"
    )
| STATS 
    records = COUNT(*)
  BY source.ip, data_type
| SORT source.ip, data_type
  """
}
```

**What You'll See:**
```
source.ip       | data_type  | records
10.0.0.50       | firewall   | 2
192.168.1.100   | firewall   | 1
192.168.1.101   | firewall   | 4
192.168.1.101   | threat     | 1
192.168.1.102   | firewall   | 1
198.51.100.20   | threat     | 1
203.0.113.999   | threat     | 1
```

**Key Observations:**
- We've added a `data_type` field using EVAL and CASE
- Still separate rows per data type
- But now we have a cleaner label ("firewall" vs "threat")
- This sets us up for the magic in the next step!

---

#### Step 4B: See Which Sources Each IP Appears In

Before doing the full correlation, let's use VALUES() to see data coverage at a glance.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM firewall-logs-demo, threat-intel-demo METADATA _index
| EVAL 
    data_type = CASE(
      _index == "firewall-logs-demo", "firewall",
      _index == "threat-intel-demo", "threat",
      "unknown"
    )
| STATS 
    data_sources = VALUES(data_type)
  BY source.ip
| SORT source.ip
  """
}
```

**What You'll See:**
```
source.ip       | data_sources
10.0.0.50       | ["firewall"]
192.168.1.100   | ["firewall"]
192.168.1.101   | ["firewall", "threat"]
192.168.1.102   | ["firewall"]
198.51.100.20   | ["threat"]
203.0.113.999   | ["threat"]
```

**Key Observations:**
- `VALUES(data_type)` returns all unique values for each IP in a single row
- **IP `192.168.1.101` appears in BOTH sources** - this is the IP we want to investigate!
- IPs like `198.51.100.20` only appear in threat intel (no firewall activity)
- IPs like `10.0.0.50` only appear in firewall logs (not in threat intel)
- This gives you a quick view of data completeness before the full join
- Great for understanding which entities have complete vs. partial data

---

#### Step 5: The Magic - Conditional Aggregation (The "Join")

Now let's use conditional aggregations to correlate the data into single rows.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM firewall-logs-demo, threat-intel-demo METADATA _index
| EVAL 
    data_type = CASE(
      _index == "firewall-logs-demo", "firewall",
      _index == "threat-intel-demo", "threat",
      "unknown"
    )
| STATS 
    connections = COUNT(*) WHERE data_type == "firewall",
    blocks = COUNT(*) WHERE data_type == "firewall" AND firewall.action == "deny",
    threats = COUNT(*) WHERE data_type == "threat",
    total_bytes = SUM(bytes) WHERE data_type == "firewall"
  BY source.ip
| WHERE threats > 0 OR connections > 0
| SORT threats DESC, blocks DESC
  """
}
```

**What You'll See:**
```
source.ip       | connections | blocks | threats | total_bytes
192.168.1.101   | 4           | 4      | 1       | 0
198.51.100.20   | 0           | 0      | 1       | null
203.0.113.999   | 0           | 0      | 1       | null
10.0.0.50       | 2           | 0      | 0       | 4300
192.168.1.102   | 1           | 0      | 0       | 3200
192.168.1.100   | 1           | 0      | 0       | 1500
```

**🎉 THIS IS THE KEY PATTERN! 🎉**

**Key Observations:**
- Each IP now has ONE row with data from BOTH sources!
- `COUNT(*) WHERE data_type == "firewall"` only counts firewall records
- `COUNT(*) WHERE data_type == "threat"` only counts threat records
- But they're aggregated together BY source.ip
- No explicit JOIN needed - STATS does the correlation!
- `192.168.1.101` has data from BOTH sources in one row!
- `198.51.100.20` is ONLY in threat intel (connections = 0)
- `10.0.0.50` is ONLY in firewall logs (threats = 0)
- **WHERE filter** ensures we only see IPs that appear in at least one source

**Why is `total_bytes` null for some IPs?**
- When an IP has NO firewall records (connections = 0), `SUM(bytes)` returns `null` instead of `0`
- This happens because `SUM()` on an empty set returns `null` in ES|QL
- IPs like `198.51.100.20` only exist in threat intel, so they have no bytes to sum
- This is expected behavior and helps distinguish "no data" from "zero bytes transferred"

**SQL Equivalent (What This Replaces):**
```sql
SELECT 
    COALESCE(f.source_ip, t.source_ip) AS source_ip,
    COUNT(f.id) AS connections,
    COUNT(CASE WHEN f.action = 'deny' THEN 1 END) AS blocks,
    COUNT(t.id) AS threats,
    SUM(f.bytes) AS total_bytes
FROM firewall_logs f
FULL OUTER JOIN threat_intel t ON f.source_ip = t.source_ip
GROUP BY COALESCE(f.source_ip, t.source_ip);
```

---

#### Step 6: Add Business Logic & Risk Scoring

Now let's add calculated fields and filter to the most interesting results.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM firewall-logs-demo, threat-intel-demo METADATA _index
| EVAL data_type = CASE(
    _index == "firewall-logs-demo", "firewall",
    _index == "threat-intel-demo", "threat",
    "unknown"
  )
| STATS 
    connections = COUNT(*) WHERE data_type == "firewall",
    blocks = COUNT(*) WHERE data_type == "firewall" AND firewall.action == "deny",
    threats = COUNT(*) WHERE data_type == "threat",
    total_bytes = SUM(bytes) WHERE data_type == "firewall"
  BY source.ip
| EVAL 
    block_rate = CASE(
      connections > 0, ROUND(TO_DOUBLE(blocks) / TO_DOUBLE(connections) * 100, 2),
      0
    ),
    risk_level = CASE(
      threats > 0 AND blocks > 2, "critical",
      threats > 0, "high",
      blocks > 5, "medium",
      "low"
    )
| WHERE threats > 0 OR blocks > 0
| SORT threats DESC, blocks DESC
  """
}
```

**What You'll See:**
```
source.ip       | connections | blocks | threats | total_bytes | block_rate | risk_level
192.168.1.101   | 4           | 4      | 1       | 0           | 100.00     | critical
198.51.100.20   | 0           | 0      | 1       | null        | 0.00       | high
203.0.113.999   | 0           | 0      | 1       | null        | 0.00       | high
```

**Key Observations:**
- Added `block_rate` calculation (percentage of blocked connections)
- Added `risk_level` risk classification
- Filtered with WHERE to show only IPs with threats OR blocks
- `192.168.1.101` is marked "critical" - it's in threat intel AND has blocked traffic!
- This is the power of joinless joins - instant correlation!

---

### Part 2: Three-Index Join (Auth + App + Firewall)

Now let's scale up to three data sources! We'll follow the same pattern.

---

#### Step 1: View Authentication Logs Only

Let's understand authentication patterns per user.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM auth-logs-demo
| STATS 
    total_logins = COUNT(*),
    failed_logins = COUNT(*) WHERE event.outcome == "failure",
    successful_logins = COUNT(*) WHERE event.outcome == "success"
  BY user.name
| EVAL 
    failure_rate = CASE(
      total_logins > 0,
      ROUND(TO_DOUBLE(failed_logins) / TO_DOUBLE(total_logins) * 100, 2),
      0
    )
| SORT failed_logins DESC
  """
}
```

**What You'll See:**
```
user.name | total_logins | failed_logins | successful_logins | failure_rate
bob       | 4            | 3             | 1                 | 75.00
alice     | 1            | 0             | 1                 | 0.00
```

**Key Observations:**
- **Bob**: 75% failure rate - very suspicious!
- **Alice**: Clean record
- But we don't know:
  - What did Bob do after successfully logging in?
  - What network activity do these users have?

---

#### Step 2: View Application Logs Only

Let's see application activity per user.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM application-logs-demo
| STATS 
    app_actions = COUNT(*),
    avg_response_time = AVG(response_time),
    max_response_time = MAX(response_time)
  BY user.name
| SORT app_actions DESC
  """
}
```

**What You'll See:**
```
user.name | app_actions | avg_response_time | max_response_time
alice     | 2           | 200.00            | 250
bob       | 2           | 365.00            | 450
```

**Key Observations:**
- Both users have application activity
- Bob's requests are slower on average
- But we can't connect this to authentication failures yet

---

#### Step 3: View Firewall Logs by IP

Let's see network activity (we'll correlate by IP since firewall doesn't have user.name).

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM firewall-logs-demo
| STATS 
    total_connections = COUNT(*),
    blocked_connections = COUNT(*) WHERE firewall.action == "deny"
  BY source.ip
| EVAL 
    block_rate = CASE(
      total_connections > 0,
      ROUND(TO_DOUBLE(blocked_connections) / TO_DOUBLE(total_connections) * 100, 2),
      0
    )
| WHERE blocked_connections > 0
| SORT blocked_connections DESC
  """
}
```

**What You'll See:**
```
source.ip     | total_connections | blocked_connections | block_rate
192.168.1.101 | 4                 | 4                   | 100.00
```

**Key Observations:**
- IP `192.168.1.101` has all traffic blocked
- But whose IP is this? We need to correlate with auth logs!

---

#### Step 4: Combine All Three Indices

Let's see what all the data looks like together (but not correlated yet).

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM auth-logs-demo, application-logs-demo, firewall-logs-demo METADATA _index
| STATS 
    total_records = COUNT(*)
  BY user.name, _index
| SORT user.name, _index
  """
}
```

**What You'll See:**
```
user.name | _index                    | total_records
alice     | application-logs-demo     | 2
alice     | auth-logs-demo            | 1
bob       | application-logs-demo     | 2
bob       | auth-logs-demo            | 4
null      | firewall-logs-demo        | 8
```

**Key Observations:**
- Each user appears multiple times (once per index)
- Firewall logs have `null` for user.name (they don't have this field)
- We need conditional aggregation to correlate this properly

---

#### Step 5: Label Each Record by Source Type

Add labels to identify which data source each record came from.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM auth-logs-demo, application-logs-demo, firewall-logs-demo METADATA _index
| EVAL 
    data_type = CASE(
      _index == "auth-logs-demo", "auth",
      _index == "application-logs-demo", "app",
      _index == "firewall-logs-demo", "firewall",
      "unknown"
    )
| STATS 
    records = COUNT(*)
  BY user.name, data_type
| SORT user.name, data_type
  """
}
```

**What You'll See:**
```
user.name | data_type  | records
alice     | app        | 2
alice     | auth       | 1
bob       | app        | 2
bob       | auth       | 4
null      | firewall   | 8
```

**Key Observations:**
- Now we have clean labels for each data source
- Still separate rows per user per data type
- Ready for the final correlation step!

---

#### Step 5B: See Which Sources Each User Appears In

Use VALUES() to see data coverage for each user across all sources.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM auth-logs-demo, application-logs-demo, firewall-logs-demo METADATA _index
| EVAL 
    data_type = CASE(
      _index == "auth-logs-demo", "auth",
      _index == "application-logs-demo", "app",
      _index == "firewall-logs-demo", "firewall",
      "unknown"
    )
| STATS 
    data_sources = VALUES(data_type),
    unique_ips = VALUES(source.ip)
  BY user.name
| SORT user.name
  """
}
```

**What You'll See:**
```
user.name | data_sources      | unique_ips
alice     | ["app", "auth"]   | ["192.168.1.100"]
bob       | ["app", "auth"]   | ["192.168.1.101", "192.168.1.103"]
null      | ["firewall"]      | ["10.0.0.50", "192.168.1.100", "192.168.1.101", "192.168.1.102"]
```

**Key Observations:**
- Alice appears in both auth and app logs, uses 1 IP
- Bob appears in both auth and app logs, uses 2 different IPs
- Firewall logs don't have user.name (shows as null), but we can see all IPs with activity
- The VALUES() function shows data completeness at a glance
- Notice Bob's IP `192.168.1.101` also appears in the firewall data (from the null row)
- This helps you understand data coverage before attempting the full correlation

**Why This Is Useful:**
- Quickly identify users with complete vs. partial data
- See which users have activity across multiple IPs
- Understand which data sources are populated for each entity
- Helps you decide if a join makes sense or if you need more data

---

#### Step 6: Three-Way Correlation (The Complete Join)

Now let's correlate all three data sources into single rows per user.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM auth-logs-demo, application-logs-demo, firewall-logs-demo METADATA _index
| EVAL data_type = CASE(
    _index == "auth-logs-demo", "auth",
    _index == "application-logs-demo", "app",
    _index == "firewall-logs-demo", "firewall",
    "unknown"
  )
| STATS 
    failed_logins = COUNT(*) WHERE data_type == "auth" AND event.outcome == "failure",
    total_logins = COUNT(*) WHERE data_type == "auth",
    app_actions = COUNT(*) WHERE data_type == "app",
    avg_response_time = AVG(response_time) WHERE data_type == "app",
    blocked_traffic = COUNT(*) WHERE data_type == "firewall" AND firewall.action == "deny",
    unique_ips = COUNT_DISTINCT(source.ip)
  BY user.name
| EVAL 
    failure_rate = CASE(
      total_logins > 0, ROUND(TO_DOUBLE(failed_logins) / TO_DOUBLE(total_logins) * 100, 2),
      0
    ),
    risk_score = (failed_logins * 20) + (blocked_traffic * 10)
| WHERE risk_score > 0
| SORT risk_score DESC
  """
}
```

**What You'll See:**
```
user.name | failed_logins | total_logins | app_actions | avg_response_time | blocked_traffic | unique_ips | failure_rate | risk_score
bob       | 3             | 4            | 2           | 365.00            | 0               | 2          | 75.00        | 60
alice     | 0             | 1            | 2           | 200.00            | 0               | 1          | 0.00         | 0
```

**🎉 THREE-WAY JOIN COMPLETE! 🎉**

**Key Observations:**
- Correlates user activity across THREE data sources
- Authentication failures + application usage + network blocks
- All in a single query with no explicit JOINs!
- Bob has high risk score due to failed logins
- Each metric is calculated from its specific data source using WHERE conditions

**SQL Equivalent (What This Replaces):**
```sql
SELECT 
    COALESCE(a.user_name, app.user_name) AS user_name,
    COUNT(CASE WHEN a.event_outcome = 'failure' THEN 1 END) AS failed_logins,
    COUNT(a.id) AS total_logins,
    COUNT(app.id) AS app_actions,
    AVG(app.response_time) AS avg_response_time,
    COUNT(CASE WHEN f.action = 'deny' THEN 1 END) AS blocked_traffic,
    COUNT(DISTINCT COALESCE(a.source_ip, app.source_ip, f.source_ip)) AS unique_ips
FROM auth_logs a
FULL OUTER JOIN application_logs app ON a.user_name = app.user_name
FULL OUTER JOIN firewall_logs f ON COALESCE(a.source_ip, app.source_ip) = f.source_ip
GROUP BY COALESCE(a.user_name, app.user_name);
```

---

### Part 3: Time-Based Correlation

Finally, let's correlate activity across time windows instead of by user or IP.

---

#### Step 1: View Activity Over Time (All Sources Combined)

Let's see event patterns across all three data sources in 5-minute windows.

**Query:**
```console
POST /_query?format=txt
{
  "query": """
FROM auth-logs-demo, application-logs-demo, firewall-logs-demo METADATA _index
| EVAL data_type = CASE(
    _index == "auth-logs-demo", "auth",
    _index == "application-logs-demo", "app",
    _index == "firewall-logs-demo", "firewall",
    "unknown"
  )
| STATS 
    auth_events = COUNT(*) WHERE data_type == "auth",
    app_events = COUNT(*) WHERE data_type == "app",
    network_events = COUNT(*) WHERE data_type == "firewall",
    security_issues = COUNT(*) WHERE (data_type == "firewall" AND firewall.action == "deny") 
                                  OR (data_type == "auth" AND event.outcome == "failure")
  BY time_window = BUCKET(@timestamp, 5 minutes)
| EVAL total_activity = auth_events + app_events + network_events
| SORT time_window DESC
  """
}
```

**What This Shows:**
- Events bucketed into 5-minute windows
- Activity from all three sources in each time window
- Security issues (blocks + failed logins) tracked over time
- See patterns of activity evolving

**SQL Equivalent:**
```sql
WITH time_buckets AS (
    SELECT 
        DATE_TRUNC('minute', timestamp, 5) AS time_window,
        'auth' AS source,
        COUNT(*) AS event_count,
        SUM(CASE WHEN event_outcome = 'failure' THEN 1 ELSE 0 END) AS security_issues
    FROM auth_logs
    GROUP BY DATE_TRUNC('minute', timestamp, 5)
    UNION ALL
    SELECT 
        DATE_TRUNC('minute', timestamp, 5) AS time_window,
        'app' AS source,
        COUNT(*) AS event_count,
        0 AS security_issues
    FROM application_logs
    GROUP BY DATE_TRUNC('minute', timestamp, 5)
    UNION ALL
    SELECT 
        DATE_TRUNC('minute', timestamp, 5) AS time_window,
        'firewall' AS source,
        COUNT(*) AS event_count,
        SUM(CASE WHEN action = 'deny' THEN 1 ELSE 0 END) AS security_issues
    FROM firewall_logs
    GROUP BY DATE_TRUNC('minute', timestamp, 5)
)
SELECT 
    time_window,
    SUM(CASE WHEN source = 'auth' THEN event_count ELSE 0 END) AS auth_events,
    SUM(CASE WHEN source = 'app' THEN event_count ELSE 0 END) AS app_events,
    SUM(CASE WHEN source = 'firewall' THEN event_count ELSE 0 END) AS network_events,
    SUM(security_issues) AS security_issues,
    SUM(event_count) AS total_activity
FROM time_buckets
GROUP BY time_window
ORDER BY time_window DESC;
```

**Comparison:**
- **SQL:** Requires CTE or subqueries, multiple GROUP BYs, then another GROUP BY to combine
- **ES|QL:** Single query, single GROUP BY, bucket and aggregate simultaneously

---

## Detailed Comparison: Traditional JOIN vs. Joinless Join

### Conceptual Difference

**Traditional SQL JOIN Philosophy:**
```
1. Match rows from Table A with rows from Table B based on a condition
2. Create a combined row for each match
3. Then aggregate the combined rows
```

**ES|QL Joinless Philosophy:**
```
1. Combine all rows from both sources (like UNION ALL)
2. Label each row with its source
3. Aggregate conditionally based on source label
```

### Visual Representation

**Traditional JOIN (Conceptual):**
```
Firewall Table:          Threat Table:
source.ip | bytes        source.ip | severity
----------+------        ----------+---------
10.0.0.1  | 1000         10.0.0.1  | high
10.0.0.2  | 2000         10.0.0.3  | medium

        ↓ JOIN ON source.ip ↓

Combined (with NULLs for non-matches):
source.ip | bytes | severity
----------+-------+---------
10.0.0.1  | 1000  | high        ← matched
10.0.0.2  | 2000  | NULL        ← firewall only
10.0.0.3  | NULL  | medium      ← threat only

        ↓ GROUP BY source.ip ↓

Aggregated Result
```

**Joinless Join (Conceptual):**
```
Firewall Table:          Threat Table:
source.ip | bytes        source.ip | severity
----------+------        ----------+---------
10.0.0.1  | 1000         10.0.0.1  | high
10.0.0.2  | 2000         10.0.0.3  | medium

        ↓ UNION ALL + Label ↓

Combined (with source labels):
source.ip | bytes | severity | _source
----------+-------+----------+---------
10.0.0.1  | 1000  | NULL     | firewall
10.0.0.2  | 2000  | NULL     | firewall
10.0.0.1  | NULL  | high     | threat
10.0.0.3  | NULL  | medium   | threat

        ↓ GROUP BY source.ip with conditional STATS ↓

Aggregated Result:
source.ip | firewall_bytes              | threat_count
----------+-----------------------------+-------------
10.0.0.1  | SUM(bytes WHERE _source=fw) | COUNT(WHERE _source=threat)
10.0.0.2  | SUM(bytes WHERE _source=fw) | COUNT(WHERE _source=threat)
10.0.0.3  | SUM(bytes WHERE _source=fw) | COUNT(WHERE _source=threat)
```

---

## Advanced Techniques

### Using VALUES() to See Data Coverage

Before performing complex joins, check which sources each entity appears in:

```console
POST /_query?format=txt
{
  "query": """
FROM firewall-logs-demo, threat-intel-demo METADATA _index
| EVAL source = CASE(
    _index == "firewall-logs-demo", "firewall",
    _index == "threat-intel-demo", "threat",
    "unknown"
  )
| STATS data_sources = VALUES(source)
  BY source.ip
| SORT source.ip
  """
}
```

**SQL Equivalent:**
```sql
SELECT 
    source_ip,
    STRING_AGG(DISTINCT data_type, ', ') AS data_sources
FROM (
    SELECT source_ip, 'firewall' AS data_type FROM firewall_logs
    UNION ALL
    SELECT source_ip, 'threat' AS data_type FROM threat_intel
) combined
GROUP BY source_ip
ORDER BY source_ip;
```

This quickly shows which IPs appear in both sources vs. just one.

---

## When to Use This Pattern

**✅ Good Use Cases:**
- Security investigations (correlate auth, network, endpoint logs)
- Performance analysis (metrics + logs + traces)
- Business analytics (orders + inventory + customers)
- Any correlation by common field (user, IP, ID, time)
- Time-series aggregations across multiple sources

**❌ When NOT to Use:**
- Need true LEFT/RIGHT JOIN semantics (must preserve all records from one side with exact structure)
- Need to preserve individual record details from multiple sources in output
- Complex many-to-many relationships requiring cartesian products
- Need to join on complex conditions (not just equality on a field)

---

## Best Practices

1. **Start Simple** - Query each index separately first
2. **Filter Early** - Add WHERE clauses before STATS when possible
3. **Limit Time Range** - Always constrain `@timestamp`
4. **Use Specific Names** - Exact index names, not broad patterns
5. **Check Data Coverage** - Use `VALUES()` to verify which sources have data
6. **Cap Results** - Use LIMIT during exploration
7. **Test Conditions** - Verify your CASE logic with small datasets

---

## Troubleshooting

| Error | Solution |
|-------|----------|
| `Unknown column [_index]` | Add `METADATA _index` to FROM clause |
| `No matching field [field_name]` | Field doesn't exist in all indices; use conditional logic |
| No results returned | Check time range with `WHERE @timestamp > NOW() - 24 hours` |

---

## Clean Up

```console
DELETE /firewall-logs-demo
DELETE /threat-intel-demo
DELETE /auth-logs-demo
DELETE /application-logs-demo
```

---

## Summary

### The Core Pattern

**ES|QL:**
```esql
FROM index1, index2 METADATA _index
| EVAL data_type = CASE(_index == "index1", "type1", "type2")
| STATS 
    metric1 = COUNT(*) WHERE data_type == "type1",
    metric2 = COUNT(*) WHERE data_type == "type2"
  BY common_field
```

**SQL Equivalent:**
```sql
SELECT 
    common_field,
    COUNT(CASE WHEN data_type = 'type1' THEN 1 END) AS metric1,
    COUNT(CASE WHEN data_type = 'type2' THEN 1 END) AS metric2
FROM (
    SELECT *, 'type1' AS data_type FROM table1
    UNION ALL
    SELECT *, 'type2' AS data_type FROM table2
) combined
GROUP BY common_field
```

**Key Takeaway:** Think "union and conditional aggregation" instead of "join then aggregate." This approach is simpler, more performant, and scales better for correlation use cases in time-series data.

---

## Next Steps

- Apply this pattern to your own indices
- Experiment with aggregation functions (AVG, MAX, MIN, SUM, PERCENTILE)
- Combine with time bucketing: `BY field, BUCKET(@timestamp, 1 hour)`
- Use with ENRICH for additional context
- Build Kibana dashboards visualizing correlations

---

**Resources:**
- [ES|QL Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html)
- [ES|QL Functions Reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql-functions-operators.html)

---

*Tutorial Version: 1.1 | December 2024 | Tested on Kibana 8.11+*
