#pragma once

#include <cstddef>
#include <iosfwd>
#include <map>
#include <optional>
#include <regex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using Fields = std::unordered_map<std::string, std::string>;

/**
 * @brief Compiled log pattern with metadata for named capture groups.
 *
 * @var Pattern::name Logical event name from the config file.
 * @var Pattern::original_regex Regular expression from YAML.
 * @var Pattern::cpp_regex Regular expression after conversion to C++ syntax.
 * @var Pattern::compiled Ready-to-use std::regex object.
 * @var Pattern::named_groups Pairs of field name and regex capture index.
 */
struct Pattern {
  std::string name;
  std::string original_regex;
  std::string cpp_regex;
  std::regex compiled;
  std::vector<std::pair<std::string, size_t>> named_groups;
};

/**
 * @brief Detection rule loaded from YAML.
 *
 * @var Rule::id Stable rule identifier.
 * @var Rule::title Human-readable rule title.
 * @var Rule::severity Alert severity: info, low, medium, high, or critical.
 * @var Rule::event Event type to which the rule applies.
 * @var Rule::type Rule type: match or threshold.
 * @var Rule::message Alert message template.
 * @var Rule::group_by Event field used by threshold rules.
 * @var Rule::threshold Minimum event count for threshold rules.
 * @var Rule::where Exact-match filters for match rules.
 */
struct Rule {
  std::string id;
  std::string title;
  std::string severity;
  std::string event;
  std::string type;
  std::string message;
  std::string group_by;
  int threshold = 1;
  Fields where;
};

/**
 * @brief Full application configuration.
 *
 * @var Config::patterns Ordered log patterns.
 * @var Config::rules Ordered detection rules.
 */
struct Config {
  std::vector<Pattern> patterns;
  std::vector<Rule> rules;
};

/**
 * @brief Parsed log event.
 *
 * @var Event::type Event type matched by a pattern.
 * @var Event::raw Original log line without surrounding whitespace.
 * @var Event::fields Captured event fields plus type and raw.
 */
struct Event {
  std::string type;
  std::string raw;
  Fields fields;
};

/**
 * @brief Alert produced by a rule.
 *
 * @var Alert::severity Alert severity.
 * @var Alert::rule_id Identifier of the rule that produced the alert.
 * @var Alert::title Rule title.
 * @var Alert::message Rendered alert message.
 */
struct Alert {
  std::string severity;
  std::string rule_id;
  std::string title;
  std::string message;
};

/**
 * @brief Aggregated statistics for parsed events and generated alerts.
 *
 * @var Stats::total_events Number of parsed events.
 * @var Stats::total_alerts Number of generated alerts.
 * @var Stats::by_type Event counts grouped by event type.
 * @var Stats::top_ips Event counts grouped by IP address.
 * @var Stats::by_severity Alert counts grouped by severity.
 */
struct Stats {
  size_t total_events = 0;
  size_t total_alerts = 0;
  std::map<std::string, int> by_type;
  std::map<std::string, int> top_ips;
  std::map<std::string, int> by_severity;
};

extern const std::vector<std::string> kSeverities;

/**
 * @brief Remove whitespace from both ends of a string.
 *
 * @param value Input string.
 * @return Trimmed copy of the input string.
 */
std::string trim(const std::string &value);

/**
 * @brief Check whether text starts with a prefix.
 *
 * @param text Text to inspect.
 * @param prefix Required prefix.
 * @return true when text begins with prefix, otherwise false.
 */
bool starts_with(const std::string &text, const std::string &prefix);

/**
 * @brief Check whether a vector contains a value.
 *
 * @param items Vector to search.
 * @param value Value to find.
 * @return true when value is present, otherwise false.
 */
bool contains(const std::vector<std::string> &items, const std::string &value);

/**
 * @brief Parse a simple inline YAML map such as {target: root}.
 *
 * @param raw Raw map text.
 * @return Parsed field map.
 * @throws std::runtime_error if the map syntax is unsupported.
 */
Fields parse_inline_map(const std::string &raw);

/**
 * @brief Convert and compile a regex with named groups.
 *
 * @param name Event name that owns the pattern.
 * @param source_regex Regex with optional (?P<name>...) captures.
 * @return Compiled pattern with named group positions.
 * @throws std::runtime_error if the regex is invalid.
 */
Pattern build_pattern(const std::string &name, const std::string &source_regex);

/**
 * @brief Load patterns and rules from a small YAML config file.
 *
 * @param path Path to the YAML config.
 * @return Validated application config.
 * @throws std::runtime_error if the file cannot be read or validation fails.
 */
Config load_config(const std::string &path);

/**
 * @brief Parse one log line against all configured patterns.
 *
 * @param line Raw log line.
 * @param patterns Ordered pattern list.
 * @return Parsed event or std::nullopt when no pattern matches.
 */
std::optional<Event> parse_line(const std::string &line,
                                const std::vector<Pattern> &patterns);

/**
 * @brief Parse all matching events from an input stream.
 *
 * @param input Stream to read.
 * @param patterns Ordered pattern list.
 * @return Parsed events.
 */
std::vector<Event> parse_stream(std::istream &input,
                                const std::vector<Pattern> &patterns);

/**
 * @brief Parse events from files or stdin.
 *
 * @param paths Log paths, empty vector, or a single "-".
 * @param patterns Ordered pattern list.
 * @return Parsed events from all inputs.
 * @throws std::runtime_error if a log file cannot be opened.
 */
std::vector<Event> parse_files(const std::vector<std::string> &paths,
                               const std::vector<Pattern> &patterns);

/**
 * @brief Read a field from an event.
 *
 * @param event Source event.
 * @param key Field name.
 * @return Field value or an empty string when missing.
 */
std::string get_field(const Event &event, const std::string &key);

/**
 * @brief Render a message template with {field} placeholders.
 *
 * @param templ Message template.
 * @param values Placeholder values.
 * @return Rendered message. Unknown placeholders remain unchanged.
 */
std::string format_message(const std::string &templ, const Fields &values);

/**
 * @brief Apply one detection rule to parsed events.
 *
 * @param rule Rule to execute.
 * @param events Parsed events.
 * @return Alerts generated by the rule.
 */
std::vector<Alert> apply_rule(const Rule &rule,
                              const std::vector<Event> &events);

/**
 * @brief Convert severity text to sortable priority.
 *
 * @param severity Severity name.
 * @return Index in severity order or -1 for unknown severity.
 */
int severity_index(const std::string &severity);

/**
 * @brief Run every rule and sort resulting alerts by severity.
 *
 * @param config Loaded config.
 * @param events Parsed events.
 * @return Sorted alerts.
 */
std::vector<Alert> run_rules(const Config &config,
                             const std::vector<Event> &events);

/**
 * @brief Keep alerts whose severity is at least the requested level.
 *
 * @param alerts Alerts to filter.
 * @param min_severity Minimum accepted severity.
 * @return Filtered alerts.
 * @throws std::runtime_error if min_severity is unknown.
 */
std::vector<Alert> filter_by_severity(const std::vector<Alert> &alerts,
                                      const std::string &min_severity);

/**
 * @brief Escape a string for JSON output.
 *
 * @param text Raw text.
 * @return JSON-safe text without surrounding quotes.
 */
std::string json_escape(const std::string &text);

/**
 * @brief Escape one CSV cell.
 *
 * @param text Raw cell value.
 * @return CSV-safe cell value.
 */
std::string csv_escape(const std::string &text);

/**
 * @brief Write alerts in JSON Lines format.
 *
 * @param alerts Alerts to write.
 * @param out Output stream.
 */
void write_json(const std::vector<Alert> &alerts, std::ostream &out);

/**
 * @brief Write alerts in CSV format.
 *
 * @param alerts Alerts to write.
 * @param out Output stream.
 */
void write_csv(const std::vector<Alert> &alerts, std::ostream &out);

/**
 * @brief Print alerts as a console table.
 *
 * @param alerts Alerts to print.
 * @param event_count Number of parsed events.
 * @param color Whether ANSI colors are enabled.
 */
void print_table(const std::vector<Alert> &alerts, size_t event_count,
                 bool color);

/**
 * @brief Build summary statistics from events and alerts.
 *
 * @param events Parsed events.
 * @param alerts Generated alerts.
 * @return Aggregated statistics.
 */
Stats compute_stats(const std::vector<Event> &events,
                    const std::vector<Alert> &alerts);

/**
 * @brief Print summary statistics to stdout.
 *
 * @param stats Statistics to print.
 * @param top_n Maximum number of IP addresses to show.
 */
void print_stats(const Stats &stats, int top_n = 5);

/**
 * @brief Print configured rule metadata to stdout.
 *
 * @param config Loaded config.
 * @param config_path Path shown in the table title.
 */
void print_rules(const Config &config, const std::string &config_path);
