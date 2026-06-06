#include "minisiem.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

std::filesystem::path make_temp_file(const std::string &name,
                                     const std::string &text) {
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / name;
  std::ofstream output(path);
  if (!output) {
    throw std::runtime_error("cannot create temporary file");
  }
  output << text;
  return path;
}

TEST(Patterns, BuildPatternMatchesAndRejects) {
  Pattern pattern = build_pattern(
      "ssh_failed", "Failed password for (?P<user>\\S+) from (?P<ip>\\S+)");
  std::vector<Pattern> patterns;
  patterns.push_back(std::move(pattern));

  auto event = parse_line("sshd: Failed password for root from 1.2.3.4 port 22",
                          patterns);
  ASSERT_TRUE(event.has_value());
  EXPECT_EQ(event->fields["user"], "root");
  EXPECT_EQ(event->fields["ip"], "1.2.3.4");

  auto missing = parse_line("ordinary log line", patterns);
  EXPECT_FALSE(missing.has_value());
}

TEST(Rules, ThresholdProducesAlertAndStaysSilentBelowLimit) {
  Rule rule;
  rule.id = "ssh_bruteforce";
  rule.title = "SSH brute-force";
  rule.severity = "high";
  rule.event = "ssh_failed";
  rule.type = "threshold";
  rule.group_by = "ip";
  rule.threshold = 3;
  rule.message = "{count} failures from {ip}";

  std::vector<Event> enough = {
      {"ssh_failed", "", {{"ip", "1.1.1.1"}}},
      {"ssh_failed", "", {{"ip", "1.1.1.1"}}},
      {"ssh_failed", "", {{"ip", "1.1.1.1"}}},
      {"ssh_failed", "", {{"ip", "2.2.2.2"}}},
  };
  std::vector<Alert> alerts = apply_rule(rule, enough);
  ASSERT_EQ(alerts.size(), 1U);
  EXPECT_EQ(alerts.front().message, "3 failures from 1.1.1.1");

  std::vector<Event> too_few = {
      {"ssh_failed", "", {{"ip", "1.1.1.1"}}},
      {"ssh_failed", "", {{"ip", "1.1.1.1"}}},
  };
  EXPECT_TRUE(apply_rule(rule, too_few).empty());
}

TEST(Rules, MatchRuleUsesWhereFilter) {
  Rule rule;
  rule.id = "sudo_root";
  rule.title = "sudo root";
  rule.severity = "medium";
  rule.event = "sudo";
  rule.type = "match";
  rule.where["target"] = "root";
  rule.message = "{cmd}";

  std::vector<Event> events = {
      {"sudo", "", {{"target", "root"}, {"cmd", "cat /etc/shadow"}}},
      {"sudo", "", {{"target", "deploy"}, {"cmd", "ls"}}},
  };

  std::vector<Alert> alerts = apply_rule(rule, events);
  ASSERT_EQ(alerts.size(), 1U);
  EXPECT_EQ(alerts.front().message, "cat /etc/shadow");

  rule.where["target"] = "nobody";
  EXPECT_TRUE(apply_rule(rule, events).empty());
}

TEST(Config, LoadValidConfigAndRejectUnknownEvent) {
  const std::string good_config =
      "patterns:\n"
      "  ssh_failed: 'Failed password for (?P<user>\\S+) from (?P<ip>\\S+)'\n"
      "rules:\n"
      "  - id: ssh_bruteforce\n"
      "    title: SSH brute-force\n"
      "    severity: high\n"
      "    event: ssh_failed\n"
      "    type: threshold\n"
      "    group_by: ip\n"
      "    threshold: 2\n"
      "    message: '{count} from {ip}'\n";

  const std::filesystem::path good =
      make_temp_file("minisiem_good_config.yaml", good_config);
  Config config = load_config(good.string());
  EXPECT_EQ(config.patterns.size(), 1U);
  EXPECT_EQ(config.rules.size(), 1U);

  const std::string bad_config = "patterns:\n"
                                 "  known: 'x'\n"
                                 "rules:\n"
                                 "  - id: broken\n"
                                 "    title: Broken\n"
                                 "    severity: low\n"
                                 "    event: missing\n"
                                 "    type: match\n"
                                 "    message: nope\n";

  const std::filesystem::path bad =
      make_temp_file("minisiem_bad_config.yaml", bad_config);
  EXPECT_THROW((void)load_config(bad.string()), std::runtime_error);
}

TEST(Severity, FilterKeepsHighEnoughAlertsAndRejectsBadSeverity) {
  std::vector<Alert> alerts = {
      {"info", "r1", "t", "m"},
      {"medium", "r2", "t", "m"},
      {"critical", "r3", "t", "m"},
  };

  std::vector<Alert> filtered = filter_by_severity(alerts, "medium");
  ASSERT_EQ(filtered.size(), 2U);
  EXPECT_EQ(filtered.front().severity, "medium");
  EXPECT_EQ(filtered.back().severity, "critical");

  EXPECT_THROW((void)filter_by_severity(alerts, "bad"), std::runtime_error);
}

TEST(Formatting, JsonAndCsvEscapingHandleSpecialCharacters) {
  EXPECT_EQ(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
  EXPECT_EQ(csv_escape("plain"), "plain");
  EXPECT_EQ(csv_escape("a,b"), "\"a,b\"");
}
