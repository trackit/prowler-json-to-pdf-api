#include "nlohmann/json.hpp"
#include <fmt/format.h>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <optional>
#include <algorithm>
#include <stdexcept>
#include <cassert>

struct ParsedProwlerReportArrayElement {
    std::string provider;
    std::string checkID;
    std::string checkTitle;
    std::vector<std::string> checkType;
    std::string serviceName;
    std::string status;
    std::string statusExtended;
    std::string severity;
    std::string resourceType;
    std::string resourceDetails;
    std::string description;
    std::string risk;
    std::string relatedUrl;
    struct {
        struct {
            std::string nativeIaC;
            std::string terraform;
            std::string cli;
            std::string other;
        } code;
        struct {
            std::string text;
            std::string url;
        } recommendation;
    } remediation;
    std::string profile;
    std::string accountID;
    std::string region;
    std::string resourceID;
    std::string resourceARN;

    bool operator==(const ParsedProwlerReportArrayElement &other)
    {
        return
            std::tie(this->provider, this->checkID, this->checkTitle, this->checkType, this->serviceName, this->status, this->statusExtended, this->severity, this->resourceType, this->resourceDetails, this->description, this->risk, this->relatedUrl, this->remediation.code.nativeIaC, this->remediation.code.terraform, this->remediation.code.cli, this->remediation.code.other, this->remediation.recommendation.text, this->remediation.recommendation.url, this->profile, this->accountID, this->region, this->resourceID, this->resourceARN) ==
            std::tie(other.provider, other.checkID, other.checkTitle, other.checkType, other.serviceName, other.status, other.statusExtended, other.severity, other.resourceType, other.resourceDetails, other.description, other.risk, other.relatedUrl, other.remediation.code.nativeIaC, other.remediation.code.terraform, other.remediation.code.cli, other.remediation.code.other, other.remediation.recommendation.text, other.remediation.recommendation.url, other.profile, other.accountID, other.region, other.resourceID, other.resourceARN);
    }
};

struct ParsedProwlerReport {
    std::set<std::string> affectedAccountIDs;
    std::vector<ParsedProwlerReportArrayElement> checks;
};

static unsigned checkSeverityStringToInt(std::string_view severity)
{
    if (severity == "critical")
        return 0;
    if (severity == "high")
        return 1;
    if (severity == "medium")
        return 2;
    if (severity == "low")
        return 3;
    return 4;
}

static auto getParsedReportFromStdin()
{
    auto inputJson = nlohmann::json::parse(std::cin);

    ParsedProwlerReport result;
    result.checks.reserve(inputJson.size());

    for (auto &i : inputJson.items()) {
        if (!i.value()["AccountId"].get<std::string>().empty())
            result.affectedAccountIDs.insert(i.value()["AccountId"].get<std::string>());
        if (i.value()["Status"].get<std::string>() != "PASS") {
            ParsedProwlerReportArrayElement parsedValue;
            parsedValue.provider = i.value()["Provider"].get<std::string>();
            parsedValue.checkID = i.value()["CheckID"].get<std::string>();
            parsedValue.checkTitle = i.value()["CheckTitle"].get<std::string>();
            parsedValue.serviceName = i.value()["ServiceName"].get<std::string>();
            parsedValue.status = i.value()["Status"].get<std::string>();
            parsedValue.statusExtended = i.value()["StatusExtended"].get<std::string>();
            parsedValue.severity = i.value()["Severity"].get<std::string>();
            parsedValue.resourceType = i.value()["ResourceType"].get<std::string>();
            parsedValue.resourceDetails = i.value()["ResourceDetails"].get<std::string>();
            parsedValue.description = i.value()["Description"].get<std::string>();
            parsedValue.risk = i.value()["Risk"].get<std::string>();
            parsedValue.relatedUrl = i.value()["RelatedUrl"].get<std::string>();
            parsedValue.remediation.code.nativeIaC = i.value()["Remediation"]["Code"]["NativeIaC"].get<std::string>();
            parsedValue.remediation.code.terraform = i.value()["Remediation"]["Code"]["Terraform"].get<std::string>();
            parsedValue.remediation.code.cli = i.value()["Remediation"]["Code"]["CLI"].get<std::string>();
            parsedValue.remediation.code.other = i.value()["Remediation"]["Code"]["Other"].get<std::string>();
            parsedValue.remediation.recommendation.text = i.value()["Remediation"]["Recommendation"]["Text"].get<std::string>();
            parsedValue.remediation.recommendation.url = i.value()["Remediation"]["Recommendation"]["Url"].get<std::string>();
            parsedValue.profile = i.value()["Profile"].get<std::string>();
            parsedValue.accountID = i.value()["AccountId"].get<std::string>();
            parsedValue.region = i.value()["Region"].get<std::string>();
            parsedValue.resourceID = i.value()["ResourceId"].get<std::string>();
            parsedValue.resourceARN = i.value()["ResourceArn"].get<std::string>();
            result.checks.push_back(parsedValue);
        }
    }

    return result;
}

static std::string stringSetToHumanReadableString(const std::set<std::string> &set)
{
    if (set.empty())
        return "";

    std::string result = *set.begin();

    for (auto it = ++set.begin(); it != set.end(); ++it) {
        auto itNext = it;
        ++itNext;
        result += (itNext == set.end() ? " and " : ", ") + *it;
    }
    return result;
}

static bool checkIDIsEc2SecurityGroupAllowIngressFromInternetToSpecificPort(std::string_view checkID)
{
    static const std::string_view checkIDs[] = {
        "ec2_securitygroup_allow_ingress_from_internet_to_port_mongodb_27017_27018",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_ftp_port_20_21",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379",
        "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23",
    };

    return std::find(std::begin(checkIDs), std::end(checkIDs), checkID) != std::end(checkIDs);
}

static bool checkIDIsEc2SecurityGroup(std::string_view checkID)
{
    return checkIDIsEc2SecurityGroupAllowIngressFromInternetToSpecificPort(checkID) ||
        checkID == "ec2_securitygroup_allow_ingress_from_internet_to_any_port" ||
        checkID == "ec2_securitygroup_not_used";
}

static bool checkIDIsEc2NetworkACLAllowIngressFromInternetToSpecificPort(std::string_view checkID)
{
    static const std::string_view checkIDs[] = {
        "ec2_networkacl_allow_ingress_tcp_port_22",
        "ec2_networkacl_allow_ingress_tcp_port_3389",
    };

    return std::find(std::begin(checkIDs), std::end(checkIDs), checkID) != std::end(checkIDs);
}

static void filterOutRedundantChecks(std::vector<ParsedProwlerReportArrayElement> &reportChecks)
{
    for (std::size_t i = 0; i < reportChecks.size(); ++i) {
        if (reportChecks.at(i).checkID == "ec2_securitygroup_allow_ingress_from_internet_to_any_port")
            for (std::size_t j = 0; j < reportChecks.size(); ++j)
                if (j != i &&
                    reportChecks.at(j).resourceARN == reportChecks.at(i).resourceARN &&
                    checkIDIsEc2SecurityGroupAllowIngressFromInternetToSpecificPort(reportChecks.at(j).checkID)) {
                    reportChecks.erase(reportChecks.begin() + j);
                    --j;
                    if (j < i)
                        --i;
                }

        if (reportChecks.at(i).checkID == "ec2_networkacl_allow_ingress_any_port")
            for (std::size_t j = 0; j < reportChecks.size(); ++j)
                if (j != i &&
                    reportChecks.at(j).resourceARN == reportChecks.at(i).resourceARN &&
                    checkIDIsEc2NetworkACLAllowIngressFromInternetToSpecificPort(reportChecks.at(j).checkID)) {
                    reportChecks.erase(reportChecks.begin() + j);
                    --j;
                    if (j < i)
                        --i;
                }

        if (reportChecks.at(i).checkID == "iam_disable_45_days_credentials")
            for (std::size_t j = 0; j < reportChecks.size(); ++j)
                if (j != i &&
                    reportChecks.at(j).resourceARN == reportChecks.at(i).resourceARN &&
                    reportChecks.at(j).checkID == "iam_disable_30_days_credentials") {
                    reportChecks.erase(reportChecks.begin() + j);
                    --j;
                    if (j < i)
                        --i;
                }

        if (reportChecks.at(i).checkID == "iam_disable_90_days_credentials")
            for (std::size_t j = 0; j < reportChecks.size(); ++j)
                if (j != i &&
                    reportChecks.at(j).resourceARN == reportChecks.at(i).resourceARN &&
                    (reportChecks.at(j).checkID == "iam_disable_45_days_credentials" || reportChecks.at(j).checkID == "iam_disable_30_days_credentials")) {
                    reportChecks.erase(reportChecks.begin() + j);
                    --j;
                    if (j < i)
                        --i;
                }

        if (reportChecks.at(i).checkID == "iam_root_hardware_mfa_enabled" &&
            std::find_if(reportChecks.begin(), reportChecks.end(), [](auto &elem)
            {
                return elem.checkID == "iam_root_mfa_enabled";
            }) != reportChecks.end()) {
            reportChecks.erase(reportChecks.begin() + i);
            --i;
        }

        // This tries to match AWS-created roles - they often fail to respect important security practises, but flagging them wouldn't be very useful and they are very common, so we skip them
        if (reportChecks.at(i).resourceARN.find(":role/aws-service-role/") != std::string::npos &&
            reportChecks.at(i).resourceARN.find("amazonaws.com/AWSServiceRoleFor") != std::string::npos) {
            reportChecks.erase(reportChecks.begin() + i);
            --i;
        }
    }
}

static bool doesStringContainRegionName(std::string_view str, std::string_view extraRegion)
{
    static const std::string_view regions[] = {
        "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-south-1", "ap-southeast-1", "ap-southeast-2",
        "ca-central-1",
        "eu-central-1", "eu-north-1", "eu-west-1", "eu-west-2", "eu-west-3",
        "sa-east-1",
        "us-east-1", "us-east-2", "us-west-1", "us-west-2"
    };

    for (auto i : regions)
        if (str.find(i) != std::string::npos)
            return true;
    return str.find(extraRegion) != std::string::npos;
}

struct ResourceARNStatusExtendedPartFetchInfo {
    std::string_view fetchedPartPrefix;
    std::optional<std::string_view> fetchedPartSuffix;
    std::string_view fetchedPartPrefixForResourceARNFormatting;
    std::string_view fetchedPartSuffixForResourceARNFormatting;
};

static const std::unordered_map<std::string, ResourceARNStatusExtendedPartFetchInfo> gResourceARNStringCheckIDToStatusExtendedPartFetchInfoMapping = {
    {"iam_policy_allows_privilege_escalation", {"allows for privilege escalation using the following actions: ", std::nullopt, " with actions: ", ""}},
    {"vpc_endpoint_connections_trust_boundaries", {" in VPC ", " has full access.", " in VPC ", ""}},
    {"ec2_instance_public_ip", {" has a Public IP: ", ").", " with public IP: ", ")"}},
    {"trustedadvisor_errors_and_warnings", {"Trusted Advisor check ", ".", " (", ")"}},
    {"elbv2_internet_facing", {" is internet facing in ", ".", " in ", ""}},
    {"cloudwatch_log_group_no_secrets_in_logs", {" in log stream ", std::nullopt, " in log stream ", ""}},
    {"iam_policy_attached_only_to_group_or_roles", {" has attached the following policy ", std::nullopt, " has policy ", ""}},
    {"awslambda_function_no_secrets_in_code", {" code -> ", std::nullopt, " in file ", ""}},
    {"awslambda_function_no_secrets_in_variables", {" variables -> ", std::nullopt, " -> ", ""}},
    {"ssm_document_secrets", {" -> ", std::nullopt, " -> ", ""}},
    {"ecs_task_definitions_no_environment_secrets", {" -> ", std::nullopt, " -> ", ""}},
    {"ec2_instance_internet_facing_with_instance_profile", {" at IP ", ".", " at IP ", ""}},
};

static std::string makeResourceARNStringFromParsedProwlerReportArrayElement(ParsedProwlerReportArrayElement parsedProwlerReportArrayElement)
{
    std::string result = !parsedProwlerReportArrayElement.resourceARN.empty() ? parsedProwlerReportArrayElement.resourceARN : parsedProwlerReportArrayElement.resourceID;

    if (result == "Security Hub" ||
        result == "EBS Default Encryption" ||
        result == "password_policy" ||
        result == "Macie" ||
        result == "No trails" ||
        result == parsedProwlerReportArrayElement.accountID)
        return "Account " + parsedProwlerReportArrayElement.accountID;

    auto statusExtendedPartFetchInfo = gResourceARNStringCheckIDToStatusExtendedPartFetchInfoMapping.find(parsedProwlerReportArrayElement.checkID);
    if (statusExtendedPartFetchInfo != gResourceARNStringCheckIDToStatusExtendedPartFetchInfoMapping.end()) {
        auto statusExtendedPrefixPos = parsedProwlerReportArrayElement.statusExtended.find(statusExtendedPartFetchInfo->second.fetchedPartPrefix);
        std::size_t statusExtendedSuffixPos;
        if (statusExtendedPartFetchInfo->second.fetchedPartSuffix.has_value())
            statusExtendedSuffixPos = parsedProwlerReportArrayElement.statusExtended.rfind(*statusExtendedPartFetchInfo->second.fetchedPartSuffix);

        if (statusExtendedPrefixPos == std::string::npos ||
            (statusExtendedPartFetchInfo->second.fetchedPartSuffix.has_value() &&
             (statusExtendedSuffixPos == std::string::npos ||
              (statusExtendedSuffixPos < (statusExtendedPrefixPos + statusExtendedPartFetchInfo->second.fetchedPartPrefix.size())))))
            fmt::print(stderr, "{}: failure to find status extended prefix or suffix for fetching part of status extended for resource ARN\n", parsedProwlerReportArrayElement.checkID);
        else
            result += std::string(statusExtendedPartFetchInfo->second.fetchedPartPrefixForResourceARNFormatting) +
                parsedProwlerReportArrayElement.statusExtended.substr(statusExtendedPrefixPos + statusExtendedPartFetchInfo->second.fetchedPartPrefix.size(), !statusExtendedPartFetchInfo->second.fetchedPartSuffix.has_value() ? std::string::npos : statusExtendedSuffixPos - (statusExtendedPrefixPos + statusExtendedPartFetchInfo->second.fetchedPartPrefix.size())) +
                std::string(statusExtendedPartFetchInfo->second.fetchedPartSuffixForResourceARNFormatting);
    }

    if (parsedProwlerReportArrayElement.region == "server" ||
        parsedProwlerReportArrayElement.serviceName == "iam" || parsedProwlerReportArrayElement.serviceName == "s3" || parsedProwlerReportArrayElement.serviceName == "trustedadvisor" ||
        doesStringContainRegionName(result, parsedProwlerReportArrayElement.region))
        return result;

    return result + " (" + parsedProwlerReportArrayElement.region + ')';
}

struct SingleCheckOutput {
    std::string checkID;
    std::string resourceARN;
    std::string statusExtended;
    std::string severity;
    std::string explanation;
    std::string recommendation;
};

struct ChecksOutputs {
    std::vector<SingleCheckOutput> outputs;
    std::set<std::string> affectedAccountIDs;
};

static auto getChecksOutputsFromStdin()
{
    auto parsedReport = getParsedReportFromStdin();

    std::stable_sort(parsedReport.checks.begin(), parsedReport.checks.end(), [](const ParsedProwlerReportArrayElement &value1, const ParsedProwlerReportArrayElement &value2)
    {
        auto severityIntValue1 = checkSeverityStringToInt(value1.severity);
        auto severityIntValue2 = checkSeverityStringToInt(value2.severity);

        return
            std::tie(severityIntValue1, value1.risk, value1.checkID, value1.serviceName, value1.statusExtended, value1.remediation.recommendation.text, value1.remediation.recommendation.url, value1.region, value1.resourceARN) <
            std::tie(severityIntValue2, value2.risk, value2.checkID, value2.serviceName, value2.statusExtended, value2.remediation.recommendation.text, value2.remediation.recommendation.url, value2.region, value2.resourceARN);
    });

    filterOutRedundantChecks(parsedReport.checks);

    ChecksOutputs checksOutputs;
    checksOutputs.affectedAccountIDs = parsedReport.affectedAccountIDs;

    for (auto &i : parsedReport.checks)
    {
        SingleCheckOutput singleCheckOutput;
        singleCheckOutput.checkID = i.checkID;
        singleCheckOutput.statusExtended = i.statusExtended;

        singleCheckOutput.resourceARN = makeResourceARNStringFromParsedProwlerReportArrayElement(i);

        singleCheckOutput.severity += fmt::format("{}", i.severity);
        singleCheckOutput.explanation += i.risk;
        singleCheckOutput.recommendation += fmt::format("{} (see also {})", i.remediation.recommendation.text, i.remediation.recommendation.url);

        checksOutputs.outputs.push_back(singleCheckOutput);
    }
    return checksOutputs;
}

static std::string removeDotAtEndOfString(std::string str)
{
    if (!str.empty() && str.back() == '.')
        str.erase(str.size() - 1);
    return str;
}

static const std::unordered_map<std::string_view, std::optional<std::string_view>> gCheckIDToIssueStatusExtendedTextMapping = {
    {"accessanalyzer_enabled", "IAM Access Analyzer is not enabled in account"},
    {"ec2_instance_secrets_user_data", "Potential secret found in EC2 instance User Data"},
    {"iam_root_hardware_mfa_enabled", std::nullopt},
    {"iam_root_mfa_enabled", std::nullopt},
    {"awslambda_function_no_secrets_in_code", "Potential secret found in Lambda function code"},
    {"awslambda_function_no_secrets_in_variables", "Potential secret found in Lambda function variable"},
    {"ssm_document_secrets", "Potential secret found in SSM Document"},
    {"iam_role_cross_service_confused_deputy_prevention", "IAM Service Role fails to prevent against a cross-service confused deputy attack"},
    {"ec2_securitygroup_allow_ingress_from_internet_to_any_port", "Security group has all ports open to the Internet"},
    {"sns_topics_kms_encryption_at_rest_enabled", "SNS topic is not encrypted"},
    {"s3_account_level_public_access_blocks", "Block Public Access is not configured in account"},
    {"sns_topics_not_publicly_accessible", "SNS topic policy has public access"},
    {"iam_user_mfa_enabled_console_access", "User has Console Password enabled but MFA disabled"},
    {"ec2_instance_managed_by_ssm", "EC2 Instance is not managed by Systems Manager"},
    {"securityhub_enabled", "Security Hub is not enabled"},
    {"directoryservice_directory_monitor_notifications", "Directory Service has SNS messaging disabled"},
    {"directoryservice_directory_log_forwarding_enabled", "Directory Service has log forwarding to CloudWatch disabled"},
    {"directoryservice_radius_server_security_protocol", "Radius server of Directory does not have recommended security protocol for the Radius server"},
    {"cloudtrail_kms_encryption_enabled", "Multiregion trail has encryption disabled"},
    {"ec2_ebs_snapshots_encrypted", "EBS Snapshot is unencrypted"},
    {"ec2_ebs_volume_encryption", "EBS Volume is unencrypted"},
    {"ec2_networkacl_allow_ingress_any_port", "Network ACL has every port open to the Internet"},
    {"ec2_networkacl_allow_ingress_tcp_port_22", "Network ACL has SSH port 22 open to the Internet"},
    {"ec2_networkacl_allow_ingress_tcp_port_3389", "Network ACL has Microsoft RDP port 3389 open to the Internet"},
    {"iam_user_hardware_mfa_enabled", "User does not have hardware MFA enabled"},
    {"s3_bucket_secure_transport_policy", "S3 Bucket does not have a bucket policy, thus it allows HTTP requests"},
    {"elbv2_deletion_protection", "ELBv2 has no deletion protection"},
    {"cloudwatch_log_group_retention_policy_specific_days_enabled", "Log Group has less than 365 days retention period"},
    {"elbv2_logging_enabled", "ELBv2 ALB has no configured access logs"},
    {"route53_public_hosted_zones_cloudwatch_logging_enabled", "Route53 Public Hosted Zone has query logging disabled"},
    {"elbv2_waf_acl_attached", "ELBv2 ALB is not protected by WAF Web ACL"},
    {"ec2_ebs_default_encryption", std::nullopt},
    {"glue_data_catalogs_connection_passwords_encryption_enabled", std::nullopt},
    {"glue_data_catalogs_metadata_encryption_enabled", std::nullopt},
    {"dynamodb_tables_pitr_enabled", "DynamoDB table does not have point-in-time recovery enabled"},
    {"cloudwatch_changes_to_network_acls_alarm_configured", "No CloudWatch log groups found with metric filters or alarms associated"},
    {"cloudwatch_changes_to_network_gateways_alarm_configured", std::nullopt},
    {"cloudwatch_changes_to_network_route_tables_alarm_configured", std::nullopt},
    {"cloudwatch_changes_to_vpcs_alarm_configured", std::nullopt},
    {"cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled", std::nullopt},
    {"cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled", std::nullopt},
    {"cloudwatch_log_metric_filter_authentication_failures", std::nullopt},
    {"efs_not_publicly_accessible", "EFS doesn't have any policy which means it grants full access to any client"},
    {"ecs_task_definitions_no_environment_secrets", "Potential secret found in variables of ECS task definition"},
    {"rds_instance_transport_encrypted", "RDS Instance connections are not encrypted"},
    {"iam_disable_90_days_credentials", "User has not used access key in the last 90 days"},
    {"ec2_instance_profile_attached", "EC2 Instance not associated with an Instance Profile Role"},
    {"account_security_contact_information_is_registered", "Manual check: Login to the AWS Console. Choose your account name on the top right of the window -> My Account -> Alternate Contacts -> Security Section and ensure security contact information is registered"},
    {"iam_rotate_access_key_90_days", "User has not rotated access key in over 90 days"},
    {"ecr_repositories_scan_images_on_push_enabled", "ECR repository has scan on push disabled"},
    {"elbv2_ssl_listeners", "ELBv2 ALB has non-encrypted listeners"},
    {"iam_policy_allows_privilege_escalation", "Customer Managed IAM Policy allows for privilege escalation using certain actions"},
    {"vpc_endpoint_connections_trust_boundaries", "VPC Endpoint has full access"},
    {"kms_cmk_rotation_enabled", "KMS CMK has automatic rotation disabled"},
    {"efs_encryption_at_rest_enabled", "EFS does not have encryption at rest enabled"},
    {"account_maintain_current_contact_details", std::nullopt},
    {"ec2_instance_public_ip", "EC2 Instance has a Public IP"},
    {"ec2_instance_older_than_specific_days", "EC2 Instance is older than 180 days"},
    {"efs_have_backup_enabled", "EFS does not have backup enabled"},
    {"rds_instance_integration_cloudwatch_logs", "RDS Instance does not have CloudWatch Logs enabled"},
    {"eks_control_plane_logging_all_types_enabled", "Control plane logging enabled but not all log types collected for EKS cluster"},
    {"trustedadvisor_errors_and_warnings", "Trusted Advisor check is in non-ok state"},
    {"rds_instance_multi_az", "RDS Instance does not have multi-AZ enabled"},
    {"cloudwatch_log_metric_filter_aws_organizations_changes", std::nullopt},
    {"cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk", std::nullopt},
    {"cloudwatch_log_metric_filter_for_s3_bucket_policy_changes", std::nullopt},
    {"cloudwatch_log_metric_filter_policy_changes", std::nullopt},
    {"cloudwatch_log_metric_filter_root_usage", std::nullopt},
    {"cloudwatch_log_metric_filter_security_group_changes", std::nullopt},
    {"cloudwatch_log_metric_filter_sign_in_without_mfa", std::nullopt},
    {"cloudwatch_log_metric_filter_unauthorized_api_calls", std::nullopt},
    {"iam_password_policy_reuse_24", std::nullopt},
    {"iam_password_policy_lowercase", std::nullopt},
    {"iam_password_policy_symbol", std::nullopt},
    {"iam_password_policy_number", std::nullopt},
    {"iam_password_policy_expires_passwords_within_90_days_or_less", std::nullopt},
    {"iam_password_policy_uppercase", std::nullopt},
    {"iam_password_policy_minimum_length_14", std::nullopt},
    {"elbv2_internet_facing", "ELBv2 ALB is internet facing"},
    {"secretsmanager_automatic_rotation_enabled", "SecretsManager secret has rotation disabled"},
    {"s3_bucket_server_access_logging_enabled", "S3 Bucket has server access logging disabled"},
    {"cloudwatch_log_group_no_secrets_in_logs", "Potential secrets found in log group"},
    {"config_recorder_all_regions_enabled", "AWS Config recorder is disabled"},
    {"account_security_questions_are_registered_in_the_aws_account", std::nullopt},
    {"iam_disable_30_days_credentials", "User has not used access key in the last 30 days"},
    {"iam_disable_45_days_credentials", "User has not used access key in the last 45 days"},
    {"ec2_instance_imdsv2_enabled", "EC2 Instance has IMDSv2 disabled or not required"},
    {"cloudwatch_log_group_kms_encryption_enabled", "Log Group does not have AWS KMS keys associated"},
    {"elbv2_insecure_ssl_ciphers", "ELBv2 has listeners with insecure SSL protocols or ciphers"},
    {"vpc_flow_logs_enabled", "VPC Flow logs are disabled"},
    {"s3_bucket_object_versioning", "S3 Bucket has versioning disabled"},
    {"cloudformation_stacks_termination_protection_enabled", "CloudFormation Stack has termination protection disabled"},
    {"rds_instance_deletion_protection", "RDS Instance deletion protection is not enabled"},
    {"s3_bucket_no_mfa_delete", "S3 Bucket has MFA Delete disabled"},
    {"accessanalyzer_enabled_without_findings", "IAM Access Analyzer is not enabled"},
    {"ecr_repositories_lifecycle_policy_enabled", "Repository has no lifecycle policy"},
    {"macie_is_enabled", std::nullopt},
    {"iam_policy_attached_only_to_group_or_roles", "User has a policy attached"},
    {"cloudtrail_s3_dataevents_read_enabled", "Not all CloudTrail trails have a data event to record all S3 object-level API operations"},
    {"cloudtrail_s3_dataevents_write_enabled", "Not all CloudTrail trails have a data event to record all S3 object-level API operations"},
    {"cloudtrail_cloudwatch_logging_enabled", "CloudTrail Trail is not logging in the last 24h or not configured to deliver log"},
    {"ec2_instance_internet_facing_with_instance_profile", "EC2 Instance is internet-facing"},
    {"directoryservice_supported_mfa_radius_enabled", "Directory does not have Radius MFA enabled"},
    {"s3_bucket_level_public_access_block", "Block Public Access is not configured for an S3 Bucket"},
    {"s3_bucket_acl_prohibited", "S3 Bucket has bucket ACLs enabled"},
    {"ec2_securitygroup_not_used", "Security group is not being used"},
    {"awslambda_function_invoke_api_operations_cloudtrail_logging_enabled", "Lambda function is not recorded by CloudTrail"},
};

struct SingleMergedChecksOutput {
    std::string checkID;
    std::set<std::string> resourceARNs;
    std::string issue;
    std::string severity;
    std::string explanation;
    std::string recommendation;
};

struct MergedChecksOutputs {
    std::set<std::string> affectedAccountIDs;
    std::vector<SingleMergedChecksOutput> outputs;
};

static std::string escapeStringForLatex(std::string_view str)
{
    std::string result;

    for (auto i : str) {
        if (i == '~') {
            result += "\textasciitilde";
            continue;
        }
        if (i == '^') {
            result += "\textasciicirnum";
            continue;
        }
        if (i == '\\') {
            result += "\textbackslash";
            continue;
        }

        if (std::string_view("&%$#_{}").find(i) != std::string::npos)
            result += '\\';
        result += i;
    }
    return result;
}

static std::string makeHighlightedTextOrWholeCellText(std::string_view highlightedText, std::string_view color, bool isForWholeTableCell)
{
    if (!isForWholeTableCell)
        return fmt::format("\\colorbox{{{}}}{{\\textbf{{{}}}}}", color, highlightedText);
    return fmt::format("\\cellcolor{{{}}}\\textbf{{{}}}", color, highlightedText);
}

static std::string severityColorForLatex(std::string_view severityStr, bool isForWholeTableCell)
{
    if (severityStr == "critical")
        return makeHighlightedTextOrWholeCellText("Critical", "DarkRed", isForWholeTableCell);
    if (severityStr == "high")
        return makeHighlightedTextOrWholeCellText("High", "red", isForWholeTableCell);
    if (severityStr == "medium")
        return makeHighlightedTextOrWholeCellText("Medium", "orange", isForWholeTableCell);
    if (severityStr == "low")
        return makeHighlightedTextOrWholeCellText("Low", "yellow", isForWholeTableCell);
    fmt::print(stderr, "{} is not a valid severity - returning raw string\n", severityStr);
    return std::string(severityStr);
}

static void makeUnnumberedSection(std::string_view sectionTitle)
{
    fmt::print("\n\\addcontentsline{{toc}}{{section}}{{{}}}\n", sectionTitle);
    fmt::print("\\section*{{{}}}\n", sectionTitle);
}

static std::string_view fixPotentialExplanationTypos(std::string_view checkID, std::string_view explanation)
{
    static const std::unordered_map<std::string_view, std::string_view> replacements = {
        {"cloudformation_stacks_termination_protection_enabled", "Without termination protection enabled, a critical cloudformation stack can be accidentally deleted. (see also https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html)"},
        {"ssm_document_secrets", "Secrets hardcoded into SSM Documents can be used by malware and bad actors to gain lateral access to other services"},
        {"directoryservice_directory_monitor_notifications", "As a best practice, monitor the status of Directory Service. This helps to avoid late actions to fix Directory Service issues"},
        {"iam_policy_attached_only_to_group_or_roles", "By default IAM users, groups and roles have no access to AWS resources. IAM policies are the means by which privileges are granted to users, groups or roles. It is recommended that IAM policies be applied directly to groups and roles but not users. Assigning privileges at the group or role level reduces the complexity of access management as the number of users grows. Reducing access management complexity may in turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges"},
    };

    const auto foundReplacement = replacements.find(checkID);
    return foundReplacement == replacements.end() ? explanation : foundReplacement->second;
}

static std::string_view fixPotentialRecommendationTypos(std::string_view checkID, std::string_view recommendation)
{
    static const std::unordered_map<std::string_view, std::string_view> replacements = {
        {"s3_bucket_object_versioning", "Configure versioning using the Amazon console or API for buckets with sensitive information that is changing frequently - note that backups may not be enough to capture all the changes"},
        {"iam_user_mfa_enabled_console_access", "Enable MFA for user accounts. MFA is a simple best practice that adds an extra layer of protection on top of your username and password. It is recommended to use hardware keys over virtual MFA (see also https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html)"},
        {"directoryservice_directory_log_forwarding_enabled", "It is recommended that the export of logs be enabled (see also https://docs.aws.amazon.com/directoryservice/latest/admin-guide/incident-response.html)"},
        {"elbv2_logging_enabled", "Enable ELB logging, create a log lifecycle and define use cases (see also https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html)"},
        {"config_recorder_all_regions_enabled", "It is recommended that AWS Config be enabled in all regions (see also https://aws.amazon.com/blogs/mt/aws-config-best-practices/)"},
        {"ec2_instance_imdsv2_enabled", "If you don't need IMDS you can turn it off. Using aws-cli you can force the instance to use only IMDSv2 (see also https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html#configuring-instance-metadata-options)"},
        {"elbv2_insecure_ssl_ciphers", "Use a Security policy with ciphers that are strong as possible. Drop legacy and insecure ciphers (see also https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies)"},
    };

    const auto foundReplacement = replacements.find(checkID);
    return foundReplacement == replacements.end() ? recommendation : foundReplacement->second;
}

void program(const std::vector<std::string> &args)
{
    if (args.size() != 2)
        throw std::runtime_error(fmt::format("Usage: {} company-name", args.at(0)));

    const std::string companyName = escapeStringForLatex(args.at(1));

    fmt::print("\\documentclass{{article}}\n");
    fmt::print("\\usepackage{{xcolor}}\n");
    fmt::print("\\usepackage{{tabto}}\n");
    fmt::print("\\usepackage{{titlesec}}\n");
    fmt::print("\\usepackage{{colortbl}}\n");
    fmt::print("\\usepackage{{longtable}}\n");
    fmt::print("\\usepackage{{graphicx}}\n");
    fmt::print("\\usepackage{{fontspec}}\n");
    fmt::print("\\begin{{document}}\n");
    fmt::print("\\setmainfont{{LiberationSans}}\n");
    fmt::print("\\begin{{sloppypar}}\n");
    fmt::print("\\raggedright\n");

    fmt::print("\n\\definecolor{{LightCyan}}{{rgb}}{{0.88,1,1}}\n");
    fmt::print("\\definecolor{{Gray}}{{gray}}{{0.9}}\n");
    fmt::print("\\definecolor{{DarkRed}}{{rgb}}{{0.8,0,0}}\n");

    fmt::print("\n\\title{{\\includegraphics[width=0.5\\textwidth]{{trackitLogo.png}}~ \\newline Security Report}}\n");
    fmt::print("\\maketitle\n");
    fmt::print("\\vspace*{{\\fill}}\n");
    fmt::print("\\begin{{center}}Business Confidential\\end{{center}}\n");
    fmt::print("\\newpage\n\n");

    fmt::print("\\tableofcontents\n");
    fmt::print("\\newpage\n\n");

    makeUnnumberedSection("Confidentiality Statement");
    fmt::print("This document is the exclusive property of \\textbf{{{}}} and \\textbf{{TrackIt}}. This document contains confidential information. Duplication, redistribution, or use, in whole or in part, in any form, requires consent of both \\textbf{{{}}} and \\textbf{{TrackIt}}.\\newline\\newline\n", companyName, companyName);
    fmt::print("{} may share this document with auditors under non-disclosure agreements to demonstrate security test requirement compliance.\n\n", companyName);

    makeUnnumberedSection("Disclaimer");
    fmt::print("A security test is considered a snapshot in time. The findings and recommendations reflect the information gathered during the assessment and not any changes or modifications made outside of that period.\\newline\\newline\n");
    fmt::print("TrackIt recommends conducting similar assessments on a regular basis by internal or third-party assessors to ensure the continued success of the controls.\n\n");

    makeUnnumberedSection("Contact Information");
    fmt::print("\\begin{{tabular}}{{ |p{{6cm}}|p{{6cm}}| }}\n");
    fmt::print(" \\hline \\rowcolor{{LightCyan}}\n");
    fmt::print(" \\begin{{center}} \\textbf{{Name}} \\end{{center}} & \\begin{{center}} \\textbf{{Contact Information}} \\end{{center}}\n");
    fmt::print(" \\\\ \\hline \\rowcolor{{Gray}}\n");
    fmt::print(" \\multicolumn{{2}}{{|l|}}{{\\textbf{{TrackIt}}}}\n");
    fmt::print(" \\\\ \\hline\n");
    fmt::print(" Gabriel Ravier & Office:\\newline Email: gabriel@trackit.io\n");
    fmt::print(" \\\\ \\hline\n");
    fmt::print("\\end{{tabular}}\n");

    fmt::print("\n\\newpage\n");
    makeUnnumberedSection("Assessment Overview");
    fmt::print("\\textbf{{{}}} has engaged TrackIt to evaluate the security posture of its infrastructure compared to current industry best practices.\\newline\\newline\n\n", companyName);
    fmt::print("\\textbf{{Tools Used}}\\newline\n");
    fmt::print("- Prowler\\newline\n");
    fmt::print("\n\\newpage\n");

    auto checksOutputs = getChecksOutputsFromStdin();

    MergedChecksOutputs mergedChecksOutputs;
    mergedChecksOutputs.affectedAccountIDs = checksOutputs.affectedAccountIDs;

    for (std::size_t i = 0; i < checksOutputs.outputs.size(); ++i) {
        SingleMergedChecksOutput nextMergedCheck;
        const auto &iElem = checksOutputs.outputs.at(i);

        nextMergedCheck.checkID = iElem.checkID;
        auto foundIssueTextMapping = gCheckIDToIssueStatusExtendedTextMapping.find(nextMergedCheck.checkID);
        if (foundIssueTextMapping == gCheckIDToIssueStatusExtendedTextMapping.end()) {
            fmt::print(stderr, "Unhandled check ID (skipped): {}\n", nextMergedCheck.checkID);
            continue;
        }

        if (!iElem.resourceARN.empty())
            nextMergedCheck.resourceARNs.insert(iElem.resourceARN);
        nextMergedCheck.issue = foundIssueTextMapping->second.has_value() ? *foundIssueTextMapping->second : removeDotAtEndOfString(iElem.statusExtended);
        nextMergedCheck.severity = iElem.severity;
        nextMergedCheck.explanation = iElem.explanation;
        nextMergedCheck.recommendation = iElem.recommendation;

        while (i < (checksOutputs.outputs.size() - 1) &&
               checksOutputs.outputs.at(i + 1).severity == nextMergedCheck.severity &&
               checksOutputs.outputs.at(i + 1).explanation == nextMergedCheck.explanation &&
               checksOutputs.outputs.at(i + 1).recommendation == nextMergedCheck.recommendation) {
            if (!checksOutputs.outputs.at(i).resourceARN.empty())
                nextMergedCheck.resourceARNs.insert(checksOutputs.outputs.at(i + 1).resourceARN);
            ++i;
        }

        nextMergedCheck.explanation = fixPotentialExplanationTypos(nextMergedCheck.checkID, removeDotAtEndOfString(nextMergedCheck.explanation));
        nextMergedCheck.recommendation = fixPotentialRecommendationTypos(nextMergedCheck.checkID, removeDotAtEndOfString(nextMergedCheck.recommendation));

        mergedChecksOutputs.outputs.push_back(std::move(nextMergedCheck));
    }

    makeUnnumberedSection("Scope");
    if (mergedChecksOutputs.affectedAccountIDs.empty())
        fmt::print("...No accounts checked ?\n\n");
    else if (mergedChecksOutputs.affectedAccountIDs.size() == 1)
        fmt::print("The {} AWS account (ID: {})\n\n", companyName, escapeStringForLatex(*mergedChecksOutputs.affectedAccountIDs.begin()));
    else {
        fmt::print("AWS accounts managed by {}, with IDs:\\newline\n", companyName);
        for (auto &i : mergedChecksOutputs.affectedAccountIDs)
            fmt::print("- {}\\newline\n", escapeStringForLatex(i));
        fmt::print("\n");
    }

    fmt::print("\n\\newpage\n");
    makeUnnumberedSection("Summary of Findings");
    fmt::print("After completing automated testing against the {} network, {} issues were identified", companyName, mergedChecksOutputs.outputs.size() != 0 ? "some" : "no");

    fmt::print("\n\\newpage\n");
    makeUnnumberedSection("Issues List");
    fmt::print("\\begin{{longtable}}{{ |p{{0.5cm}}|p{{10cm}}|p{{2cm}}|p{{2cm}}| }}\n");
    fmt::print(" \\hline \\rowcolor{{LightCyan}}\n");
    fmt::print(" \\multicolumn{{1}}{{|c|}}{{\\textbf{{\\#}}}} & Issue & \\multicolumn{{1}}{{|c|}}{{Severity}} & Status\n");
    fmt::print(" \\\\ \\hline\n");
    for (std::size_t i = 0; i < mergedChecksOutputs.outputs.size(); ++i) {
        const auto &iElem = mergedChecksOutputs.outputs.at(i);

        fmt::print(" {}", i + 1);
        fmt::print(" & {}", escapeStringForLatex(iElem.issue));
        fmt::print(" & {}", severityColorForLatex(escapeStringForLatex(iElem.severity), true));
        fmt::print(" & \\textcolor{{red}}{{Open}}\n");
        fmt::print(" \\\\ \\hline\n");
    }
    fmt::print("\\end{{longtable}}\n\n");

    for (std::size_t i = 0; i < mergedChecksOutputs.outputs.size(); ++i) {
        const auto &iElem = mergedChecksOutputs.outputs.at(i);

        fmt::print("\\newpage\n\n");

        fmt::print("\\subsection*{{Issue \\#{} - {}}}\n", i + 1, escapeStringForLatex(iElem.issue));

        fmt::print("Severity\\tab : {}\\newline\n", severityColorForLatex(escapeStringForLatex(iElem.severity), false));
        fmt::print("Status\\tab : \\textcolor{{red}}{{Open}}\\newline\\newline\n");
        if (iElem.resourceARNs.size() == 1)
            fmt::print("\\textbf{{Affected resource:}} {}\\newline\n", escapeStringForLatex(*iElem.resourceARNs.begin()));
        else if (iElem.resourceARNs.size() != 0) {
            fmt::print("\\textbf{{Affected resources:}}\\newline\n");
            for (auto &j : iElem.resourceARNs)
                fmt::print("- {}\\newline\n", escapeStringForLatex(j));
        }
        fmt::print("\\newline\n\\textbf{{Risk:}}\\newline\n\\newline\n{}\\newline\n", escapeStringForLatex(iElem.explanation));
        fmt::print("\\newline\n\\textbf{{Recommendation:}}\\newline\n\\newline\n{}\\newline\n", escapeStringForLatex(iElem.recommendation));

        if (i != mergedChecksOutputs.outputs.size() - 1)
            fmt::print("\n\n");
    }

    fmt::print("\\end{{sloppypar}}\n");
    fmt::print("\\end{{document}}\n");
}

int main(int argc, char *argv[])
{
    try {
        const std::vector<std::string> args(argv, argv + argc);
        program(args);
        return 0;
    } catch (std::exception &exc) {
        fmt::print(stderr, "Error (stdexcept): {}\n", exc.what());
        return 84;
    } catch (...) {
        fmt::print(stderr, "Error: Unknown exception !!!!!!\n");
        return 84;
    }
}
