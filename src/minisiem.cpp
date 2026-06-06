#include "minisiem.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

const std::vector<std::string> kSeverities = {"info", "low", "medium", "high",
                                              "critical"};

const std::vector<std::string> kRequiredRuleKeys = {
    "id", "title", "severity", "event", "type", "message"};

/**
 * @brief Remove whitespace from both ends of a string.
 *
 * @param value Input string.
 * @return Trimmed copy of the input string.
 */
std::string trim(const std::string &value) {
  const auto begin =
      std::find_if_not(value.begin(), value.end(),
                       [](unsigned char c) { return std::isspace(c); });
  const auto end =
      std::find_if_not(value.rbegin(), value.rend(), [](unsigned char c) {
        return std::isspace(c);
      }).base();
  if (begin >= end) {
    return "";
  }
  return std::string(begin, end);
}

/**
 * @brief Count leading spaces in a config line.
 *
 * @param line Source line.
 * @return Number of leading space characters.
 */
int count_indent(const std::string &line) {
  int count = 0;
  for (char c : line) {
    if (c == ' ') {
      ++count;
    } else {
      break;
    }
  }
  return count;
}

/**
 * @brief Check whether text starts with a prefix.
 *
 * @param text Text to inspect.
 * @param prefix Required prefix.
 * @return true when text begins with prefix.
 */
bool starts_with(const std::string &text, const std::string &prefix) {
  return text.rfind(prefix, 0) == 0;
}

/**
 * @brief Check whether a vector contains a value.
 *
 * @param items Vector to search.
 * @param value Value to find.
 * @return true when value is present.
 */
bool contains(const std::vector<std::string> &items, const std::string &value) {
  return std::find(items.begin(), items.end(), value) != items.end();
}

/**
 * @brief Remove an unquoted YAML inline comment.
 *
 * @param value Raw scalar value.
 * @return Value without an inline comment.
 */
std::string strip_inline_comment(const std::string &value) {
  bool in_single = false;
  bool in_double = false;
  for (size_t i = 0; i < value.size(); ++i) {
    char c = value[i];
    if (c == '\'' && !in_double) {
      in_single = !in_single;
    } else if (c == '"' && !in_single) {
      in_double = !in_double;
    } else if (c == '#' && !in_single && !in_double) {
      if (i == 0 || std::isspace(static_cast<unsigned char>(value[i - 1]))) {
        return trim(value.substr(0, i));
      }
    }
  }
  return trim(value);
}

/**
 * @brief Remove surrounding quotes from a YAML scalar when present.
 *
 * @param raw Raw scalar value.
 * @return Unquoted scalar value.
 */
std::string unquote(const std::string &raw) {
  std::string value = strip_inline_comment(raw);
  if (value.size() >= 2) {
    char first = value.front();
    char last = value.back();
    if ((first == '\'' && last == '\'') || (first == '"' && last == '"')) {
      value = value.substr(1, value.size() - 2);
    }
  }
  return value;
}

/**
 * @brief Split a YAML key-value line at the first colon.
 *
 * @param text YAML line without indentation.
 * @return Pair of trimmed key and value.
 * @throws std::runtime_error if the line has no colon.
 */
std::pair<std::string, std::string> split_key_value(const std::string &text) {
  const size_t colon = text.find(':');
  if (colon == std::string::npos) {
    throw std::runtime_error("bad YAML line: " + text);
  }
  return {trim(text.substr(0, colon)), trim(text.substr(colon + 1))};
}

/**
 * @brief Parse a simple inline YAML map such as {target: root}.
 *
 * @param raw Raw map text.
 * @return Parsed field map.
 * @throws std::runtime_error if the map syntax is unsupported.
 */
Fields parse_inline_map(const std::string &raw) {
  Fields result;
  std::string value = trim(raw);
  if (value.empty()) {
    return result;
  }
  if (value.front() != '{' || value.back() != '}') {
    throw std::runtime_error("expected inline map like {key: value}");
  }
  value = value.substr(1, value.size() - 2);
  std::stringstream ss(value);
  std::string item;
  while (std::getline(ss, item, ',')) {
    item = trim(item);
    if (item.empty()) {
      continue;
    }
    auto [key, map_value] = split_key_value(item);
    result[key] = unquote(map_value);
  }
  return result;
}

/**
 * @brief Read a UTF-8 text file into lines.
 *
 * @param path File path.
 * @return Lines without trailing carriage returns.
 * @throws std::runtime_error if the file cannot be opened.
 */
std::vector<std::string> read_lines(const std::string &path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("cannot open " + path);
  }

  std::vector<std::string> lines;
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    lines.push_back(line);
  }
  return lines;
}

/**
 * @brief Convert and compile a regex with named groups.
 *
 * @param name Event name that owns the pattern.
 * @param source_regex Regex with optional (?P<name>...) captures.
 * @return Compiled pattern with named group positions.
 * @throws std::runtime_error if the regex is invalid.
 */
Pattern build_pattern(const std::string &name,
                      const std::string &source_regex) {
  Pattern pattern;
  pattern.name = name;
  pattern.original_regex = source_regex;

  size_t capture_index = 0;
  bool in_class = false;
  for (size_t i = 0; i < source_regex.size(); ++i) {
    char c = source_regex[i];

    if (c == '\\') {
      pattern.cpp_regex.push_back(c);
      if (i + 1 < source_regex.size()) {
        pattern.cpp_regex.push_back(source_regex[++i]);
      }
      continue;
    }

    if (c == '[') {
      in_class = true;
      pattern.cpp_regex.push_back(c);
      continue;
    }

    if (c == ']' && in_class) {
      in_class = false;
      pattern.cpp_regex.push_back(c);
      continue;
    }

    if (!in_class && c == '(') {
      if (source_regex.compare(i, 4, "(?P<") == 0) {
        const size_t name_begin = i + 4;
        const size_t name_end = source_regex.find('>', name_begin);
        if (name_end == std::string::npos) {
          throw std::runtime_error("bad named group in pattern " + name);
        }
        ++capture_index;
        const std::string group_name =
            source_regex.substr(name_begin, name_end - name_begin);
        pattern.named_groups.push_back({group_name, capture_index});
        pattern.cpp_regex.push_back('(');
        i = name_end;
        continue;
      }

      if (i + 1 < source_regex.size() && source_regex[i + 1] == '?') {
        pattern.cpp_regex.push_back(c);
        continue;
      }

      ++capture_index;
    }

    pattern.cpp_regex.push_back(c);
  }

  try {
    pattern.compiled = std::regex(pattern.cpp_regex);
  } catch (const std::regex_error &error) {
    throw std::runtime_error("bad regex '" + name + "': " + error.what());
  }
  return pattern;
}

/**
 * @brief Store one YAML rule property in a Rule object.
 *
 * @param rule Rule being filled.
 * @param seen Map of fields already seen in YAML.
 * @param key YAML key.
 * @param raw_value YAML value before unquoting.
 * @throws std::runtime_error if threshold is not an integer.
 */
void set_rule_value(Rule &rule, std::map<std::string, bool> &seen,
                    const std::string &key, const std::string &raw_value) {
  const std::string value = unquote(raw_value);
  seen[key] = true;

  if (key == "id") {
    rule.id = value;
  } else if (key == "title") {
    rule.title = value;
  } else if (key == "severity") {
    rule.severity = value;
  } else if (key == "event") {
    rule.event = value;
  } else if (key == "type") {
    rule.type = value;
  } else if (key == "message") {
    rule.message = value;
  } else if (key == "group_by") {
    rule.group_by = value;
  } else if (key == "threshold") {
    try {
      rule.threshold = std::stoi(value);
    } catch (const std::exception &) {
      throw std::runtime_error("rule " + rule.id +
                               " has non-integer threshold");
    }
  } else if (key == "where") {
    rule.where = parse_inline_map(raw_value);
  }
}

/**
 * @brief Validate that a rule is complete and internally consistent.
 *
 * @param rule Rule to validate.
 * @param seen Set of fields present in YAML.
 * @param patterns Available event patterns.
 * @param path Config path used in error messages.
 * @throws std::runtime_error if validation fails.
 */
void validate_rule(const Rule &rule, const std::map<std::string, bool> &seen,
                   const std::vector<Pattern> &patterns,
                   const std::string &path) {
  for (const std::string &key : kRequiredRuleKeys) {
    auto it = seen.find(key);
    if (it == seen.end() || !it->second) {
      throw std::runtime_error(path + ": rule " +
                               (rule.id.empty() ? "?" : rule.id) +
                               " misses required field " + key);
    }
  }

  if (rule.type != "match" && rule.type != "threshold") {
    throw std::runtime_error(path + ": rule " + rule.id + " has unknown type " +
                             rule.type);
  }
  if (!contains(kSeverities, rule.severity)) {
    throw std::runtime_error(path + ": rule " + rule.id + " has bad severity " +
                             rule.severity);
  }

  const bool event_exists = std::any_of(
      patterns.begin(), patterns.end(),
      [&](const Pattern &pattern) { return pattern.name == rule.event; });
  if (!event_exists) {
    throw std::runtime_error(path + ": rule " + rule.id +
                             " references unknown event " + rule.event);
  }

  if (rule.type == "threshold" && rule.group_by.empty()) {
    throw std::runtime_error(path + ": threshold rule " + rule.id +
                             " requires group_by");
  }
}

/**
 * @brief Load patterns and rules from a small YAML config file.
 *
 * @param path Path to the YAML config.
 * @return Validated application config.
 * @throws std::runtime_error if the file cannot be read or validation fails.
 */
Config load_config(const std::string &path) {
  try {
    const std::vector<std::string> lines = read_lines(path);
    Config config;
    std::string section;
    Rule current_rule;
    std::map<std::string, bool> current_seen;
    bool in_rule = false;
    bool in_where = false;

    auto finish_rule = [&]() {
      if (!in_rule) {
        return;
      }
      validate_rule(current_rule, current_seen, config.patterns, path);
      config.rules.push_back(current_rule);
      current_rule = Rule{};
      current_seen.clear();
      in_rule = false;
      in_where = false;
    };

    for (const std::string &raw_line : lines) {
      const std::string stripped = trim(raw_line);
      if (stripped.empty() || starts_with(stripped, "#")) {
        continue;
      }

      const int indent = count_indent(raw_line);
      if (indent == 0) {
        finish_rule();
        const auto [key, value] = split_key_value(stripped);
        if (!value.empty()) {
          throw std::runtime_error(path +
                                   ": top-level section must not have a value");
        }
        section = key;
        continue;
      }

      if (section == "patterns" && indent >= 2) {
        auto [key, value] = split_key_value(stripped);
        config.patterns.push_back(build_pattern(key, unquote(value)));
        continue;
      }

      if (section == "rules") {
        if (starts_with(stripped, "- ")) {
          finish_rule();
          in_rule = true;
          const std::string rest = trim(stripped.substr(2));
          if (!rest.empty()) {
            auto [key, value] = split_key_value(rest);
            set_rule_value(current_rule, current_seen, key, value);
          }
          continue;
        }

        if (!in_rule) {
          throw std::runtime_error(path + ": rule property without a rule");
        }

        auto [key, value] = split_key_value(stripped);
        if (indent <= 4) {
          in_where = false;
        }

        if (key == "where" && value.empty()) {
          current_seen[key] = true;
          in_where = true;
          continue;
        }

        if (in_where && indent >= 6) {
          current_rule.where[key] = unquote(value);
          continue;
        }

        set_rule_value(current_rule, current_seen, key, value);
      }
    }

    finish_rule();

    if (config.patterns.empty()) {
      throw std::runtime_error(path + ": section 'patterns' is empty");
    }
    if (config.rules.empty()) {
      throw std::runtime_error(path + ": section 'rules' is empty");
    }
    return config;
  } catch (const std::exception &error) {
    throw std::runtime_error("config error: " + std::string(error.what()));
  }
}

/**
 * @brief Parse one log line against all configured patterns.
 *
 * @param line Raw log line.
 * @param patterns Ordered pattern list.
 * @return Parsed event or std::nullopt when no pattern matches.
 */
std::optional<Event> parse_line(const std::string &line,
                                const std::vector<Pattern> &patterns) {
  for (const Pattern &pattern : patterns) {
    std::smatch match;
    if (!std::regex_search(line, match, pattern.compiled)) {
      continue;
    }

    Event event;
    event.type = pattern.name;
    event.raw = trim(line);
    event.fields["type"] = event.type;
    event.fields["raw"] = event.raw;

    for (const auto &[name, index] : pattern.named_groups) {
      if (index < match.size()) {
        event.fields[name] = match[index].str();
      }
    }
    return event;
  }
  return std::nullopt;
}

/**
 * @brief Parse all matching events from an input stream.
 *
 * @param input Stream to read.
 * @param patterns Ordered pattern list.
 * @return Parsed events.
 */
std::vector<Event> parse_stream(std::istream &input,
                                const std::vector<Pattern> &patterns) {
  std::vector<Event> events;
  std::string line;
  while (std::getline(input, line)) {
    auto event = parse_line(line, patterns);
    if (event.has_value()) {
      events.push_back(std::move(*event));
    }
  }
  return events;
}

/**
 * @brief Parse events from files or stdin.
 *
 * @param paths Log paths, empty vector, or a single "-".
 * @param patterns Ordered pattern list.
 * @return Parsed events from all inputs.
 * @throws std::runtime_error if a log file cannot be opened.
 */
std::vector<Event> parse_files(const std::vector<std::string> &paths,
                               const std::vector<Pattern> &patterns) {
  std::vector<Event> events;
  if (paths.empty() || (paths.size() == 1 && paths.front() == "-")) {
    return parse_stream(std::cin, patterns);
  }

  for (const std::string &path : paths) {
    std::ifstream input(path);
    if (!input) {
      throw std::runtime_error("cannot open log file " + path);
    }
    std::vector<Event> file_events = parse_stream(input, patterns);
    events.insert(events.end(), std::make_move_iterator(file_events.begin()),
                  std::make_move_iterator(file_events.end()));
  }
  return events;
}

/**
 * @brief Read a field from an event.
 *
 * @param event Source event.
 * @param key Field name.
 * @return Field value or an empty string when missing.
 */
std::string get_field(const Event &event, const std::string &key) {
  auto it = event.fields.find(key);
  if (it == event.fields.end()) {
    return "";
  }
  return it->second;
}

/**
 * @brief Render a message template with {field} placeholders.
 *
 * @param templ Message template.
 * @param values Placeholder values.
 * @return Rendered message. Unknown placeholders remain unchanged.
 */
std::string format_message(const std::string &templ, const Fields &values) {
  std::string output;
  for (size_t i = 0; i < templ.size(); ++i) {
    if (templ[i] == '{') {
      const size_t end = templ.find('}', i + 1);
      if (end != std::string::npos) {
        const std::string key = templ.substr(i + 1, end - i - 1);
        auto it = values.find(key);
        output += (it == values.end()) ? "{" + key + "}" : it->second;
        i = end;
        continue;
      }
    }
    output.push_back(templ[i]);
  }
  return output;
}

/**
 * @brief Apply one detection rule to parsed events.
 *
 * @param rule Rule to execute.
 * @param events Parsed events.
 * @return Alerts generated by the rule.
 */
std::vector<Alert> apply_rule(const Rule &rule,
                              const std::vector<Event> &events) {
  std::vector<Alert> alerts;

  if (rule.type == "match") {
    for (const Event &event : events) {
      if (event.type != rule.event) {
        continue;
      }

      bool accepted = true;
      for (const auto &[key, expected] : rule.where) {
        if (get_field(event, key) != expected) {
          accepted = false;
          break;
        }
      }

      if (accepted) {
        alerts.push_back({rule.severity, rule.id, rule.title,
                          format_message(rule.message, event.fields)});
      }
    }
    return alerts;
  }

  if (rule.type == "threshold") {
    std::map<std::string, int> counts;
    for (const Event &event : events) {
      if (event.type == rule.event) {
        counts[get_field(event, rule.group_by)]++;
      }
    }

    for (const auto &[value, count] : counts) {
      if (count >= rule.threshold) {
        Fields context;
        context[rule.group_by] = value;
        context["count"] = std::to_string(count);
        alerts.push_back({rule.severity, rule.id, rule.title,
                          format_message(rule.message, context)});
      }
    }
  }

  return alerts;
}

/**
 * @brief Convert severity text to sortable priority.
 *
 * @param severity Severity name.
 * @return Index in severity order or -1 for unknown severity.
 */
int severity_index(const std::string &severity) {
  auto it = std::find(kSeverities.begin(), kSeverities.end(), severity);
  if (it == kSeverities.end()) {
    return -1;
  }
  return static_cast<int>(std::distance(kSeverities.begin(), it));
}

/**
 * @brief Run every rule and sort resulting alerts by severity.
 *
 * @param config Loaded config.
 * @param events Parsed events.
 * @return Sorted alerts.
 */
std::vector<Alert> run_rules(const Config &config,
                             const std::vector<Event> &events) {
  std::vector<Alert> alerts;
  for (const Rule &rule : config.rules) {
    std::vector<Alert> rule_alerts = apply_rule(rule, events);
    alerts.insert(alerts.end(), std::make_move_iterator(rule_alerts.begin()),
                  std::make_move_iterator(rule_alerts.end()));
  }

  std::sort(
      alerts.begin(), alerts.end(), [](const Alert &left, const Alert &right) {
        return severity_index(left.severity) > severity_index(right.severity);
      });
  return alerts;
}

/**
 * @brief Keep alerts whose severity is at least the requested level.
 *
 * @param alerts Alerts to filter.
 * @param min_severity Minimum accepted severity.
 * @return Filtered alerts.
 * @throws std::runtime_error if min_severity is unknown.
 */
std::vector<Alert> filter_by_severity(const std::vector<Alert> &alerts,
                                      const std::string &min_severity) {
  const int floor = severity_index(min_severity);
  if (floor < 0) {
    throw std::runtime_error("unknown min severity: " + min_severity);
  }

  std::vector<Alert> filtered;
  for (const Alert &alert : alerts) {
    if (severity_index(alert.severity) >= floor) {
      filtered.push_back(alert);
    }
  }
  return filtered;
}

/**
 * @brief Escape a string for JSON output.
 *
 * @param text Raw text.
 * @return JSON-safe text without surrounding quotes.
 */
std::string json_escape(const std::string &text) {
  std::ostringstream out;
  for (unsigned char c : text) {
    switch (c) {
    case '\\':
      out << "\\\\";
      break;
    case '"':
      out << "\\\"";
      break;
    case '\n':
      out << "\\n";
      break;
    case '\r':
      out << "\\r";
      break;
    case '\t':
      out << "\\t";
      break;
    default:
      if (c < 0x20) {
        out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<int>(c);
      } else {
        out << static_cast<char>(c);
      }
    }
  }
  return out.str();
}

/**
 * @brief Escape one CSV cell.
 *
 * @param text Raw cell value.
 * @return CSV-safe cell value.
 */
std::string csv_escape(const std::string &text) {
  const bool needs_quotes = text.find_first_of("\",\n\r") != std::string::npos;
  if (!needs_quotes) {
    return text;
  }
  std::string out = "\"";
  for (char c : text) {
    if (c == '"') {
      out += "\"\"";
    } else {
      out.push_back(c);
    }
  }
  out += '"';
  return out;
}

void write_json(const std::vector<Alert> &alerts, std::ostream &out) {
  for (const Alert &alert : alerts) {
    out << "{\"severity\":\"" << json_escape(alert.severity)
        << "\",\"rule_id\":\"" << json_escape(alert.rule_id)
        << "\",\"title\":\"" << json_escape(alert.title) << "\",\"message\":\""
        << json_escape(alert.message) << "\"}\n";
  }
}

void write_csv(const std::vector<Alert> &alerts, std::ostream &out) {
  out << "severity,rule_id,title,message\n";
  for (const Alert &alert : alerts) {
    out << csv_escape(alert.severity) << ',' << csv_escape(alert.rule_id) << ','
        << csv_escape(alert.title) << ',' << csv_escape(alert.message) << '\n';
  }
}

std::string color_code(const std::string &severity) {
  if (severity == "info")
    return "\033[36m";
  if (severity == "low")
    return "\033[32m";
  if (severity == "medium")
    return "\033[33m";
  if (severity == "high")
    return "\033[31m";
  if (severity == "critical")
    return "\033[1;37;41m";
  return "";
}

void print_table(const std::vector<Alert> &alerts, size_t event_count,
                 bool color) {
  std::cout << "mini-SIEM - events: " << event_count
            << ", alerts: " << alerts.size() << "\n\n";
  std::cout << std::left << std::setw(12) << "Severity" << std::setw(22)
            << "Rule"
            << "Message\n";
  std::cout << std::string(80, '-') << "\n";

  for (const Alert &alert : alerts) {
    std::string severity = alert.severity;
    std::transform(
        severity.begin(), severity.end(), severity.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    if (color) {
      std::cout << color_code(alert.severity) << std::left << std::setw(12)
                << severity << "\033[0m";
    } else {
      std::cout << std::left << std::setw(12) << severity;
    }
    std::cout << std::setw(22) << alert.rule_id << alert.message << "\n";
  }
}

Stats compute_stats(const std::vector<Event> &events,
                    const std::vector<Alert> &alerts) {
  Stats stats;
  stats.total_events = events.size();
  stats.total_alerts = alerts.size();

  for (const Event &event : events) {
    stats.by_type[event.type]++;
    const std::string ip = get_field(event, "ip");
    if (!ip.empty()) {
      stats.top_ips[ip]++;
    }
  }

  for (const Alert &alert : alerts) {
    stats.by_severity[alert.severity]++;
  }
  return stats;
}

template <typename Map>
std::vector<std::pair<std::string, int>> sorted_counts(const Map &counts) {
  std::vector<std::pair<std::string, int>> items(counts.begin(), counts.end());
  std::sort(items.begin(), items.end(),
            [](const auto &left, const auto &right) {
              if (left.second != right.second) {
                return left.second > right.second;
              }
              return left.first < right.first;
            });
  return items;
}

void print_stats(const Stats &stats, int top_n) {
  std::cout << "\nSummary\n";
  std::cout << "  Total events: " << stats.total_events << "\n";
  std::cout << "  Total alerts: " << stats.total_alerts << "\n";
  for (auto it = kSeverities.rbegin(); it != kSeverities.rend(); ++it) {
    auto found = stats.by_severity.find(*it);
    if (found != stats.by_severity.end()) {
      std::cout << "  " << *it << ": " << found->second << "\n";
    }
  }

  std::cout << "\nEvents by type\n";
  for (const auto &[type, count] : sorted_counts(stats.by_type)) {
    std::cout << "  " << std::left << std::setw(18) << type << count << "\n";
  }

  if (!stats.top_ips.empty()) {
    std::cout << "\nTop IP addresses\n";
    int printed = 0;
    for (const auto &[ip, count] : sorted_counts(stats.top_ips)) {
      if (printed++ >= top_n) {
        break;
      }
      std::cout << "  " << std::left << std::setw(18) << ip << count << "\n";
    }
  }
}

void print_rules(const Config &config, const std::string &config_path) {
  std::cout << "Rules from " << config_path << "\n\n";
  std::cout << std::left << std::setw(24) << "id" << std::setw(12) << "type"
            << std::setw(10) << "severity"
            << "event\n";
  std::cout << std::string(70, '-') << "\n";
  for (const Rule &rule : config.rules) {
    std::cout << std::left << std::setw(24) << rule.id << std::setw(12)
              << rule.type << std::setw(10) << rule.severity << rule.event
              << "\n";
  }
}
