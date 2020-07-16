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
  auditlog-fields  Retrieve Audit log Query fields.
  list-auditlogs   Retrieve CLI diff in Audit log.
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

To list the CLI differences in the audit logs for last 1 hour, run the command `python3 audit-logs.py list-auditlogs` on macOS/Ubuntu env or `py -3.7 audit-logs.py list-auditlogs` on windows env

**Query Payload:**

- Below Query retrieves the Audit logs related to `template` changes in `last 1 hour`

```
{
    "query": {
                "condition": "AND",
                "rules": [
                        {
                            "value": [
                            "1"
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
python3 audit-logs.py list-auditlogs

@@ -204,7 +204,7 @@

    dns 8.8.8.8 primary
    host test ip 10.10.10.1
    interface ge0/2
-    ip address 192.168.30.30/24
+    ip address 192.168.30.1/24
     no shutdown
    !
    interface natpool1
```
