# Introduction

This document describes installing a Microsoft SQL Server (MSSQL) Always On
Availability Group (AAG). The solution consists of two Windows Server nodes,
each of which are running MSSQL and Windows Server Failover Clustering (WSFC)
services. With MSSQL and WSFC installed and configured, the MSSQL Always On
Availability Group feature is then enabled. AAG helps manage database
replication and failover services between the members of the WSFC cluster.

In addition, there is a third Windows Server instance that acts as a witness
for the WSFC cluster. The witness provides an extra layer of availability in
the event of network partitioning between the members of the WSFC cluster
(the MSSQL instances).

# Prerequisites

-   Amazon AWS VPC configured
-   Amazon AWS CLI configured, with credentials
-   URIs to MSSQL ISO and other software
-   Parameter map for the target environment must be complete
-   URI to the **MSSQL AlwaysOn CloudFormation Template**
-   URI to the **MSSQL AlwaysOn Parameter Map**

# Prepare the Active Directory Domain

Microsoft WSFC has several dependencies on Microsoft Active Directory Domain
Services that must be met prior to beginning the deployment of the MSSQL
AlwaysOn Availability Group.

This set of information is specific to an environment, and so will need to be
available when completing the parameter map for the environment.

1.  Create an Organizational Unit (OU) container.
2.  Create a service account user, placed within the OU.
3.  Select a cluster name (e.g. WSFC1), and create a Cluster Name Object (CNO)
    with that name within the OU. The CNO is a disabled computer object, and so
    is subject to NetBIOS limitations on the computer object (typically, a
    maximum length of 15 alpha-numeric characters). NOTE: It is _critical_ for
    the CNO to be disabled. WSFC will enable the object when creating the
    cluster. If the object is already enabled, WSFC will fail to create the
    cluster and the deployment _will fail_.
4.  Grant the service account full control of the CNO.
5.  Grant the CNO permissions to the OU to create computer objects.

For detailed steps, see the document from Microsoft, [Prestage Cluster Computer Objects in Active Directory Domain Services][0].

# Identify Required Parameters for this Build

1.  Select a computer name for **Node 1**.
2.  Select a computer name for **Node 2**.
3.  Select a computer name for the **Witness**.
4.  Select 3 available IP addresses for **Node 1**. All 3 IPs must be in the
    IP range associated with the `MssqlNode1SubnetId` parameter.
5.  Select 3 available IP addresses for **Node 2**. All 3 IPs must be in the
    IP range associated with the `MssqlNode2SubnetId` parameter.
6.  Optionally, select an available IP address for the **Witness**. If not
    specified, a free IP will be assigned automatically. If specified, the IP
    must be in the IP range associated with the `WitnessSubnetId` parameter.
    Since the Witness is launched first, this can be useful when the subnet
    range is small, increasing the chances of a conflict with an IP assigned to
    an MSSQL Node.

# Install Methods

There are two install methods, via the AWS CLI or via the AWS Console. Pick
one.

## Install using the AWS CLI

Follow the instructions in this section to deploy the MSSQL AlwaysOn
Availability Group using the AWS CLI. These commands are written from a Linux
shell. If you are not comfortable with the CLI, then see the next section,
[Install using the AWS Console](#install-using-the-aws-console).

### Setup the CLI

1.  Select a parameter map file that matches the environment (See
    [Prerequisites](#prerequisites)).

2.  Set the environment variables:

    ```bash
    PARAM_MAP="https://url/to/db_mssql_alwayson.params.json"
    TEMPLATE="https://s3.amazonaws.com/app-chemistry/templates/db_mssql_alwayson.compound"
    ```

3.  Set the variables for the MSSQL AlwayOn build (Some params may be hard-
    coded in the parameter map; be sure to check it first):

    ```bash
    APPENV=
    CLUSTERNAME=
    DNSIPADDRESSES=
    DOMAINDNS=
    DOMAINNETBIOS=
    EXTRASGID=
    INSTANCEROLE=
    KEYPAIR=
    MSSQLINSTANCETYPE=
    NODE1NAME=
    NODE1IP1=
    NODE1IP2=
    NODE1IP3=
    NODE1SUBNET=
    NODE2NAME=
    NODE2IP1=
    NODE2IP2=
    NODE2IP3=
    NODE2SUBNET=
    OSADMINGROUPS=
    OUPATH=
    SQLADMINGROUP=
    SQLPRODUCTKEY=
    SVCACCOUNT=
    SVCACCOUNTPASSWORD=
    WITNESSINSTANCETYPE=
    WITNESSIP=
    WITNESSNAME=
    WITNESSSUBNET=
    VPC=
    ```

4.  Retrieve the current Windows 2012 R2 AMI ID (Windows 2016 is also likely
    to work):

    ```bash
    AMIPATTERN="Windows_Server-2012-R2_RTM-English-64Bit-Base-*"
    AMI=$(aws ec2 describe-images \
        --filters \
        Name="name",Values="${AMIPATTERN}" \
        Name="is-public",Values="true" \
        Name="owner-alias",Values="amazon" \
        --query 'reverse(Images.sort_by([], &Name))[0].[ImageId]' \
        --out text)
    echo $AMI  # May want to doublecheck this output correctly selected the AMI
    ```

5.  Retrieve the parameter map and update it with the variables for this build:

    ```bash
    curl -O "${PARAM_MAP}"
    PARAM_MAP_FILE="${PARAM_MAP##*/}"  # Gets the filename from the PARAM_MAP URI
    SVCACCOUNTPASSWORD=$(sed 's/[&/\]/\\&/g' <<< "${SVCACCOUNTPASSWORD}")  # Escapes special characters in the password for the following sed expression
    sed -i -e "{
        s/__AMIID__/${AMI}/
        s/__APPENV__/${APPENV}/
        s/__CLUSTERNAME__/${CLUSTERNAME}/
        s/__DNSIPADDRESSES__/${DNSIPADDRESSES}/
        s/__DOMAINDNS__/${DOMAINDNS}/
        s/__DOMAINNETBIOS__/${DOMAINNETBIOS}/
        s/__EXTRASGID__/${EXTRASGID}/
        s/__INSTANCEROLE__/${INSTANCEROLE}/
        s/__KEYPAIR__/${KEYPAIR}/
        s/__MSSQLINSTANCETYPE__/${MSSQLINSTANCETYPE}/
        s/__NODE1NAME__/${NODE1NAME}/
        s/__NODE1IP1__/${NODE1IP1}/
        s/__NODE1IP2__/${NODE1IP2}/
        s/__NODE1IP3__/${NODE1IP3}/
        s/__NODE1SUBNET__/${NODE1SUBNET}/
        s/__NODE2NAME__/${NODE2NAME}/
        s/__NODE2IP1__/${NODE2IP1}/
        s/__NODE2IP2__/${NODE2IP2}/
        s/__NODE2IP3__/${NODE2IP3}/
        s/__NODE2SUBNET__/${NODE2SUBNET}/
        s/__OSADMINGROUPS__/${OSADMINGROUPS}/
        s/__OUPATH__/${OUPATH}/
        s/__OUPATH__/${OUPATH}/
        s/__SQLADMINGROUP__/${SQLADMINGROUP}/
        s/__SQLPRODUCTKEY__/${SQLPRODUCTKEY}/
        s/__SVCACCOUNT__/${SVCACCOUNT}/
        s/__WITNESSINSTANCETYPE__/${WITNESSINSTANCETYPE}/
        s/__WITNESSIP__/${WITNESSIP}/
        s/__WITNESSNAME__/${WITNESSNAME}/
        s/__WITNESSSUBNET__/${WITNESSSUBNET}/
        s/__VPC__/${VPC}/
    }" "${PARAM_MAP_FILE}"
    ```

### Launch the stack

1.  Set the stack name:

    ```bash
    STACK=""  # E.g. AAG01
    ```

2.  Use the AWS CLI and the parameter map to launch the stack:

    ```bash
    aws cloudformation create-stack \
        --stack-name "${STACK}" \
        --template-url "${TEMPLATE}" \
        --parameters "file://${PARAM_MAP_FILE}"
    ```

3.  The AWS CLI should return a StackId. Login to the AWS Console to monitor
the progress of the stack creation. It should take approximately 90 minutes.

## Install using the AWS Console

Follow the instructions in this section to deploy the MSSQL AlwaysOn
Availability Group using the AWS Console. This section describes an alternative
to the method described in the prior section, [Install using the AWS
CLI](#install-using-the-aws-cli). If you completed that section, skip this
section.

### Setup the Stack

1.  Login to the Amazon AWS Console
2.  Once authenticated, use this link to filter for Windows Server 2012 R2 AMIs
    created by Amazon (Windows 2016 is also likely to work):
    -   <https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#Images:visibility=public-images;search=Windows_Server-2012-R2_RTM-English-64Bit-Base-%2A;ownerAlias=amazon;sort=desc:name>
3.  Pick the most recent AMI and note the AMI ID. This will be used in the
    `AmiId` field when launching the Cloudformation stack.
4.  Navigate to _CloudFormation_ Service
5.  Press the _Create Stack_ button
6.  Choose a template and _Specify an Amazon S3 Template URL_
7.  Enter:
    -   <https://s3.amazonaws.com/app-chemistry/templates/db_mssql_alwayson.compound>
8.  Press the _Next_ button
9.  Input a _Stack name_ E.g. `MSSQLAAG01`. This name will be tagged to all
    resources created by this template.

### Enter the Stack Parameters

This section describes the parameters needed to launch the stack. For each
parameter, the value for the environment should be retrieved from the
Parameter-Environment Map file (see [Prerequisites](#prerequisites)).

**Network Configuration**

-   `DnsServerIpAddresses`
    -   (Optional) Sets static DNS Servers on EC2 instances; comma-delimited
        list of DNS Server IP addresses
-   `MssqlNode1SubnetId`
    -   ID of the subnet for the first MSSQL node
-   `MssqlNode2SubnetId`
    -   ID of the subnet for the second MSSQL node
-   `WitnessSubnetId`
    -   ID of the subnet for the Witness server
-   `VPC`
    -   ID of the VPC

**EC2 Instance Configuration**

-   `AmiId`
    -   ID of the AMI to use for all instances
-   `ExtraSecurityGroupId`
    -   (Optional) An extra security group to apply to the instances -- template
        always creates security groups required for intra-cluster communication
-   `InstanceRole`
    -   IAM role to assign to the instances
-   `KeyPairName`
    -   Keypair to allow you to securely connect to the instance after it
    launches
-   `NoPublicIp`
    -   Controls whether to assign the instance a public IP. Recommended to
        leave at "true". If launching in a public subnet, then this parameter
        must be set to "false"
-   `NoReboot`
    -   Controls whether to reboot the instance as the last step of cfn-init
        execution

**EC2 Domain Configuration**

-   `DomainDnsName`
    -   Fully qualified domain name (FQDN) of the forest root domain, e.g.
        corp.example.com
-   `DomainNetbiosName`
    -   NetBIOS name of the domain (upto 15 characters), e.g. EXAMPLE

**EC2 SystemPrep Configuration**

-   `SystemPrepBootstrapUrl`
    -   URL to the SystemPrep Bootstrapper
-   `SystemPrepEnvironment`
    -   Environment in which the instance is being deployed. Values of **dev**,
        **test**, or **prod** will result in applying enterprise integrations
        (E.g. Splunk, McAfee HBSS, and joining the Active Directory domain).
        **false** will skip any enterprise integrations.
-   `SystemPrepOuPath`
    -   DN of the OU to place the instance when joining a domain. If blank and
        `SystemPrepEnvironment` enforces a domain join, the instance will be
        placed in a default container. Leave blank if not joining a domain, or
        if `SystemPrepEnvironment` is **false**
-   `SystemPrepAdminGroups`
    -   Colon-separated list of domain groups that should have admin
        permissions on the EC2 instance.

**EC2 MSSQL Cluster Configuration**

-   `MssqlInstanceType`
    -   EC2 instance type for the MSSQL servers
-   `MssqlNode1NetbiosName`
    -   NetBIOS name of the 1st MSSQL Node (up to 15 characters)
-   `MssqlNode1PrivateIp`
    -   Primary private IP for the 1st MSSQL Node located in AZ1
-   `MssqlNode1PrivateIp2`
    -   Secondary private IP for MSSQL cluster on 1st MSSQL Node
-   `MssqlNode1PrivateIp3`
    -   Third private IP for Availability Group Listener on 1st MSSQL Node
-   `MssqlNode2NetbiosName`
    -   NetBIOS name of the 2nd MSSQL Node (up to 15 characters)
-   `MssqlNode2PrivateIp`
    -   Primary private IP for the 2nd MSSQL Node located in AZ2
-   `MssqlNode2PrivateIp2`
    -   Secondary private IP for MSSQL cluster on 2nd MSSQL Node
-   `MssqlNode2PrivateIp3`
    -   Third private IP for Availability Group Listener on 2nd MSSQL Node
-   `ClusterName`
    -   NetBIOS name of the Windows Server Failover Cluster (up to 15
        characters)
-   `SqlAdminGroup`
    -   Name of the domain group that will have admin rights to the MSSQL
        database
-   `Sql Service Account`
    -   User name for the SQL Server Service Account. This Account is a Domain
        User.
-   `Sql Service Account Password`
    -   Password for the SQL Service account.
-   `SqlProductKey`
    -   (Optional) Specifies the product key for the edition of SQL Server. If
        this parameter is left blank, Evaluation is used.
-   `CarbonUrl`
    -   URL to the Carbon PowerShell Module zip file
-   `PsToolsUrl`
    -   URL to the PSTools zip file
-   `Configure Sql AlwaysOn Script Url`
    -   URL to the SQL Server AlwaysOn Configuration Script
-   `ConfigureWsfcScriptUrl`
    -   URL to the WSFC Configuration Script
-   `Set Dns Search Suffix Script Url`
    -   URL to the DNS Search Suffix Script
-   `InstallSqlScriptUrl`
    -   URL to the SQL Server Install Script
-   `InstallWsfcScriptUrl`
    -   URL to the WSFC Install Script
-   `SourcesSxsUrl`
    -   URL to the sources/sxs zip file for Windows Server 2012 R2
-   `SqlIsoUrl`
    -   URL to the SQL Server ISO file

**EC2 Witness Configuration**

-   `WitnessInstanceType`
    -   EC2 instance type for the Witness server
-   `WitnessPrivateIp`
    -   Primary private IP for the Witness server
-   `WitnessNetbiosName`
    -   NetBIOS name of the Witness server (up to 15 characters)

**CloudFormation Configuration**

-   `CfnEndpointUrl`
    -   URL to the CloudFormation Endpoint. E.g. <https://cloudformation.us-east-1.amazonaws.com>
-   `Force Cfn Init Update`
    -   Toggle that forces a change to instance metadata. Used during a
        CloudFormation stack update to trigger the cfn-init "update" sequence,
        even when the CloudFormation template has not otherwise changed.

### Run the Stack

1.  After entering the stack parameters, press the _Next_ button
2.  (Optional) In the Options page, expand the Advanced panel and set
    _Rollback on failure_ to **Yes**
3.  In the Options page, press the _Next_ button
4.  Review the information
5.  Press the _Create_ button
6.  Monitor the stack for success. It should take approximately 90 minutes to
    complete.

## Post-Install Steps

Depending on the domain policies, and the SQL version, there may be a couple
more things to do to finish configuring the SQL Servers.

1.  Delete SQL SPNs associated with the SQL Node Computer Accounts.

    ```powershell
    setspn -D MSSQLSvc/<NODE1NAME>.<DOMAINDNS>:1433 <NODE1NAME>
    setspn -D MSSQLSvc/<NODE1NAME>.<DOMAINDNS> <NODE1NAME>
    setspn -D MSSQLSvc/<NODE2NAME>.<DOMAINDNS>:1433 <NODE2NAME>
    setspn -D MSSQLSvc/<NODE2NAME>.<DOMAINDNS> <NODE2NAME>
    ```

2.  For SQL 2012, grant the `SYSTEM` account permissions to manage availability
    groups. See [Microsoft Support Article 2847723][2847723].

    ```sql
    USE [master]
    GO
    CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
    GO

    GRANT ALTER ANY AVAILABILITY GROUP TO [NT AUTHORITY\SYSTEM]
    GO
    GRANT CONNECT SQL TO [NT AUTHORITY\SYSTEM]
    GO
    GRANT VIEW SERVER STATE TO [NT AUTHORITY\SYSTEM]
    GO
    ```

## Final SQL AlwaysOn Configuration

The last piece of the SQL AlwaysOn installation is to create a database and add
it to an availability group. This is covered in Part 3 of Amazon's Quick Start
guide on setting up a [SQL AlwaysOn Availability Group][1].

[0]: <https://technet.microsoft.com/en-us/library/dn466519(v=ws.11).aspx>
[1]: <http://docs.aws.amazon.com/quickstart/latest/sql/part3.html>
[2847723]: <https://support.microsoft.com/en-us/help/2847723/cannot-create-a-high-availability-group-in-microsoft-sql-server-2012>
