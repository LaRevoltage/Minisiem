#include "minisiem.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

struct CliOptions {
  std::vector<std::string> logs;
  std::string config_path = "config.yaml";
  std::string output_path;
  std::string min_severity = "info";
  bool json = false;
  bool csv = false;
  bool stats = false;
  bool list_rules = false;
  bool no_color = false;
};

void print_help(const char *program) {
  std::cout
      << "Usage: " << program << " [options] <logs...>\n\n"
      << "Options:\n"
      << "  -c, --config PATH       YAML config path (default: config.yaml)\n"
      << "      --json              write alerts as JSONL\n"
      << "      --csv               write alerts as CSV\n"
      << "      --stats             print event and alert statistics\n"
      << "  -o, --output PATH       write alerts to file\n"
      << "      --min-severity LVL  info, low, medium, high, critical\n"
      << "      --list-rules        show configured rules and exit\n"
      << "      --no-color          disable ANSI colors\n"
      << "  -h, --help              show this help\n";
}

std::string require_value(int &index, int argc, char *argv[],
                          const std::string &option) {
  if (index + 1 >= argc) {
    throw std::runtime_error(option + " requires a value");
  }
  return argv[++index];
}

CliOptions parse_args(int argc, char *argv[]) {
  CliOptions options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      print_help(argv[0]);
      std::exit(0);
    } else if (arg == "-c" || arg == "--config") {
      options.config_path = require_value(i, argc, argv, arg);
    } else if (arg == "--json") {
      options.json = true;
    } else if (arg == "--csv") {
      options.csv = true;
    } else if (arg == "--stats") {
      options.stats = true;
    } else if (arg == "-o" || arg == "--output") {
      options.output_path = require_value(i, argc, argv, arg);
    } else if (arg == "--min-severity") {
      options.min_severity = require_value(i, argc, argv, arg);
    } else if (arg == "--list-rules") {
      options.list_rules = true;
    } else if (arg == "--no-color") {
      options.no_color = true;
    } else if (starts_with(arg, "-") && arg != "-") {
      throw std::runtime_error("unknown option: " + arg);
    } else {
      options.logs.push_back(arg);
    }
  }

  if (options.json && options.csv) {
    throw std::runtime_error("--json and --csv cannot be used together");
  }
  if (!contains(kSeverities, options.min_severity)) {
    throw std::runtime_error("unknown severity: " + options.min_severity);
  }
  return options;
}

int run(const CliOptions &options) {
  Config config = load_config(options.config_path);

  if (options.list_rules) {
    print_rules(config, options.config_path);
    return 0;
  }

  if (options.logs.empty()) {
    throw std::runtime_error("no log files passed; use '-' for stdin");
  }

  std::vector<Event> events = parse_files(options.logs, config.patterns);
  std::vector<Alert> alerts =
      filter_by_severity(run_rules(config, events), options.min_severity);

  if (!options.output_path.empty() && (options.csv || options.json)) {
    std::ofstream output(options.output_path);
    if (!output) {
      throw std::runtime_error("cannot open output file " +
                               options.output_path);
    }
    if (options.csv) {
      write_csv(alerts, output);
    } else {
      write_json(alerts, output);
    }
  } else if (options.csv) {
    write_csv(alerts, std::cout);
  } else if (options.json) {
    write_json(alerts, std::cout);
  } else {
    print_table(alerts, events.size(), !options.no_color);
  }

  if (options.stats) {
    print_stats(compute_stats(events, alerts));
  }
  return 0;
}

int main(int argc, char *argv[]) {
  try {
    const CliOptions options = parse_args(argc, argv);
    return run(options);
  } catch (const std::regex_error &error) {
    std::cerr << "Regex error: " << error.what() << "\n";
    return 2;
  } catch (const std::exception &error) {
    std::cerr << "Error: " << error.what() << "\n";
    return 1;
  } catch (...) {
    std::cerr << "Unknown error\n";
    return 1;
  }
}
