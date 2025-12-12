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

## Progressive Examples

### Example 1: Two-Index Join (Firewall + Threat Intel)

#### Understanding the Approach

**SQL Equivalent (What You Might Expect):**
```sql
SELECT 
    COALESCE(f.source_ip, t.source_ip) AS source_ip,
    COUNT(f.id) AS connections,
    COUNT(CASE WHEN f.action = 'deny' THEN 1 END) AS blocks,
    COUNT(t.id) AS threats,
    SUM(f.bytes) AS total_bytes,
    ROUND(100.0 * COUNT(CASE WHEN f.action = 'deny' THEN 1 END) / COUNT(f.id), 2) AS block_rate
FROM firewall_logs f
FULL OUTER JOIN threat_intel t ON f.source_ip = t.source_ip
GROUP BY COALESCE(f.source_ip, t.source_ip)
HAVING COUNT(t.id) > 0 OR COUNT(CASE WHEN f.action = 'deny' THEN 1 END) > 0
ORDER BY COUNT(t.id) DESC, COUNT(CASE WHEN f.action = 'deny' THEN 1 END) DESC;
```

**ES|QL Joinless Approach:**

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

**How It Works:**

1. **FROM both indices** - Like a UNION ALL in SQL, combining all records
2. **Label each record** - EVAL creates a `data_type` field (like adding a source indicator column)
3. **Conditional aggregation** - `COUNT(*) WHERE data_type == "firewall"` is like `COUNT(CASE WHEN source = 'firewall' THEN 1 END)`
4. **GROUP BY source.ip** - Correlates records from both sources
5. **Filter & sort** - Post-aggregation filtering

**Key Insight:** Instead of joining two tables, we union them, label them, and aggregate conditionally!

---

### Example 2: Three-Index Join (Auth + App + Firewall)

#### Understanding the Three-Way Join

**SQL Equivalent (Traditional Approach):**
```sql
SELECT 
    COALESCE(a.user_name, app.user_name) AS user_name,
    COUNT(CASE WHEN a.event_outcome = 'failure' THEN 1 END) AS failed_logins,
    COUNT(a.id) AS total_logins,
    COUNT(app.id) AS app_actions,
    AVG(app.response_time) AS avg_response_time,
    COUNT(CASE WHEN f.action = 'deny' THEN 1 END) AS blocked_traffic,
    COUNT(DISTINCT COALESCE(a.source_ip, app.source_ip, f.source_ip)) AS unique_ips,
    ROUND(100.0 * COUNT(CASE WHEN a.event_outcome = 'failure' THEN 1 END) / NULLIF(COUNT(a.id), 0), 2) AS failure_rate,
    (COUNT(CASE WHEN a.event_outcome = 'failure' THEN 1 END) * 20) + 
    (COUNT(CASE WHEN f.action = 'deny' THEN 1 END) * 10) AS risk_score
FROM auth_logs a
FULL OUTER JOIN application_logs app ON a.user_name = app.user_name
FULL OUTER JOIN (
    SELECT source_ip, action 
    FROM firewall_logs
) f ON COALESCE(a.source_ip, app.source_ip) = f.source_ip
GROUP BY COALESCE(a.user_name, app.user_name)
HAVING (COUNT(CASE WHEN a.event_outcome = 'failure' THEN 1 END) * 20) + 
       (COUNT(CASE WHEN f.action = 'deny' THEN 1 END) * 10) > 0
ORDER BY risk_score DESC;
```

**Problems with SQL Approach:**
- Complex nested FULL OUTER JOINs
- Multiple COALESCE calls to handle NULLs
- Expensive cartesian products before filtering
- Difficult to maintain and debug

**ES|QL Joinless Approach:**

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

**How It Works:**

1. **FROM three indices** - Union all records from all sources
2. **Single CASE statement** - Labels each record with its source (one operation vs. multiple joins)
3. **Parallel conditional aggregations** - Each metric calculated independently with WHERE filters
4. **Single GROUP BY** - Correlates everything by `user.name` in one pass
5. **Post-aggregation logic** - Calculate derived metrics after grouping

**Why This Is Better:**
- ✅ Single data pass (vs. multiple join operations)
- ✅ No cartesian products
- ✅ Easy to add more sources (just add to FROM and CASE)
- ✅ Natural handling of missing data (NULLs handled automatically)
- ✅ More readable and maintainable

---

### Example 3: Time-Based Correlation

#### Understanding Time-Series Joins

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

**ES|QL Joinless Approach:**

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

### Performance Comparison

| Aspect | Traditional JOIN | ES|QL Joinless |
|--------|-----------------|----------------|
| **Data Passes** | 2+ (one per table, then join) | 1 (read all, aggregate once) |
| **Memory** | High (must store join results) | Lower (streaming aggregation) |
| **Complexity** | O(n*m) in worst case | O(n+m) |
| **Scalability** | Degrades with more tables | Scales linearly |
| **NULL Handling** | Explicit (COALESCE, IFNULL) | Implicit (conditional COUNT) |

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
