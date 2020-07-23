# sdwan-audit-log-apis

# Objective 

*   How to use vManage APIs to retrieve Audit logs and CLI diff

# Requirements

To use this code you will need:

* Python 3.7+
* vManage user login details. (User should have privilege level to configure policies)

# Install and Setup

- Clone the code to local machine.

```
git clone https://github.com/suchandanreddy/sdwan-audit-log-apis
cd sdwan-audit-log-apis
```
- Setup Python Virtual Environment (requires Python 3.7+)

```
python3.7 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

- Setup local environment variables to provide vManage login details. 

Examples:

For macOS and Ubuntu Environment:

```
export vmanage_host=10.10.10.10
export vmanage_port=443
export username=admin
export password=admin
```

For Windows Environment:

```
set vmanage_host=10.10.10.10
set vmanage_port=443
set username=admin
set password=admin
```
After setting the env variables, run the python script `audit-logs.py` using the command `python3 audit-logs.py` for macOS or Ubuntu env and `py -3.7 audit-logs.py` for windows env to see all the CLI command options available in `audit-logs.py`

**Sample Response:**

```
python3 audit-logs.py
Usage: audit-logs.py [OPTIONS] COMMAND [ARGS]...

  Command line tool for retrieving CLI diff in Audit logs.

Options:
  --help  Show this message and exit.

Commands:
  auditlog-fields         Retrieve Audit log Query fields.
  list-auditlogs          Retrieve CLI diff in Audit logs for custom start...
  list-n-hours-auditlogs  Retrieve CLI diff in Audit logs for last n hours...
```

**Example-1:**

To list the Query fields supported by Audit log APIs, run the command `python3 audit-logs.py auditlog-fields` on macOS/Ubuntu env or `py -3.7 audit-logs.py auditlog-fields` on windows env

**Sample Response:**

```
python3 audit-logs.py auditlog-fields

entry_time(date)  logmodule(string)   loguser(string)     logdeviceid(string)  logprocessid(string)
logid(string)     logfeature(string)  logmessage(string)  logdetails(string)
```

**Example-2:** 

To list the CLI differences in the audit logs for last 2 hours, run the command `python3 audit-logs.py list-n-hours-auditlogs --last_n_hours 2` on macOS/Ubuntu env or `py -3.7 audit-logs.py list-n-hours-auditlogs --last_n_hours 2` on windows env

**Query Payload:**

- Below Query retrieves the Audit logs related to `template` changes in `last n hours` based on the user input of number of hours value.

```
{
    "query": {
                "condition": "AND",
                "rules": [
                        {
                            "value": [
                            <last_n_hours>
                            ],
                            "field": "entry_time",
                            "type": "date",
                            "operator": "last_n_hours"
                        },
                        {
                            "value": [
                            "template"
                            ],
                            "field": "logmodule",
                            "type": "string",
                            "operator": "in"
                        }
                        ]
                     }
}
```

**Sample Response:**

```
python3 audit-logs.py list-n-hours-auditlogs --help
Usage: audit-logs.py list-n-hours-auditlogs [OPTIONS]

  Retrieve CLI diff in Audit logs for last n hours
  Example command: ./audit-logs.py list_auditlogs

Options:
  --last_n_hours TEXT  Audit logs for last n hours
  --help               Show this message and exit.
```

```
python3 audit-logs.py list-n-hours-auditlogs --last_n_hours 2
╒═════════════════════╤════════╤═════════════╤══════════╤════════════════════════════════════════════════════════════════════════════════════════════════════╕
│ Date                │ User   │ User IP     │ Device   │ Message                                                                                            │
╞═════════════════════╪════════╪═════════════╪══════════╪════════════════════════════════════════════════════════════════════════════════════════════════════╡
│ 07/23/2020 08:31:40 │ admin  │ 10.24.31.49 │ 1.1.1.6  │ Template updated_20_1_BR2-CSR-1000v successfully attached to device 1.1.1.6 with personality:vedge │
╘═════════════════════╧════════╧═════════════╧══════════╧════════════════════════════════════════════════════════════════════════════════════════════════════╛
---

+++

@@ -307,7 +307,7 @@

    no shutdown
    arp timeout 1200
    vrf forwarding 10
-   ip address 192.168.40.4 255.255.255.0
+   ip address 192.168.40.1 255.255.255.0
    ip directed-broadcast
    no ip redirects
    ip mtu    1500
@@ -484,11 +484,6 @@

    flow-visibility
    no implicit-acl-logging
    log-frequency        1000
-   policer 100M
-    rate   100000000
-    burst  10000000
-    exceed drop
-   !
    lists
     data-prefix-list BR2-Prefix-list
      ip-prefix 192.168.40.0/24
```

In the above output `-` refers to the new configuration after template is pushed and `+` to the old configuration before template is pushed.

**Example-3:** 

To list the CLI differences in the audit logs between a start and end date, run the command `python3 audit-logs.py list-auditlogs` on macOS/Ubuntu env or `py -3.7 audit-logs.py list-auditlogs` on windows env

**Query Payload:**

- Below Query retrieves the Audit logs related to `template` changes between `start_date` and `end_date` based on the user input.

```
{
    "query": {
               "condition": "AND",
               "rules": [
                        {
                            "value": [
                                       start_date+"T00:00:00 UTC",
                                       end_date+"T23:59:59 UTC" 
                            ],
                            "field": "entry_time",
                            "type": "date",
                            "operator": "between"
                        },
                        {
                            "value": [
                            "template"
                            ],
                            "field": "logmodule",
                            "type": "string",
                            "operator": "in"
                        }
                        ]
              }
}
```

**Sample Response:**

```
python3 audit-logs.py list-auditlogs --help
Usage: audit-logs.py list-auditlogs [OPTIONS]

  Retrieve CLI diff in Audit logs for custom start and end date
  Example command: ./audit-logs.py list_auditlogs

Options:
  --help  Show this message and exit.
```

```
python3 audit-logs.py list-auditlogs
Please enter start date(YYYY-MM-DD): 2020-07-22
Please enter end date(YYYY-MM-DD): 2020-07-23
╒═════════════════════╤════════╤═════════════╤══════════╤════════════════════════════════════════════════════════════════════════════════════════════════════╕
│ Date                │ User   │ User IP     │ Device   │ Message                                                                                            │
╞═════════════════════╪════════╪═════════════╪══════════╪════════════════════════════════════════════════════════════════════════════════════════════════════╡
│ 07/23/2020 08:31:40 │ admin  │ 10.24.31.49 │ 1.1.1.6  │ Template updated_20_1_BR2-CSR-1000v successfully attached to device 1.1.1.6 with personality:vedge │
╘═════════════════════╧════════╧═════════════╧══════════╧════════════════════════════════════════════════════════════════════════════════════════════════════╛
---

+++

@@ -307,7 +307,7 @@

    no shutdown
    arp timeout 1200
    vrf forwarding 10
-   ip address 192.168.40.4 255.255.255.0
+   ip address 192.168.40.1 255.255.255.0
    ip directed-broadcast
    no ip redirects
    ip mtu    1500
@@ -484,11 +484,6 @@

    flow-visibility
    no implicit-acl-logging
    log-frequency        1000
-   policer 100M
-    rate   100000000
-    burst  10000000
-    exceed drop
-   !
    lists
     data-prefix-list BR2-Prefix-list
      ip-prefix 192.168.40.0/24
```