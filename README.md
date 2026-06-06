# mini-SIEM

`mini-SIEM` - консольный анализатор Linux-логов на C++. Он читает правила из
`config.yaml`, парсит строки логов регулярными выражениями и формирует алерты:
SSH brute-force, sudo от root, несуществующие пользователи, баны fail2ban и
другие события, описанные в конфиге.

Регулярки и правила лежат в `config.yaml`, а C++-код только загружает и
исполняет их. Чтобы добавить новый тип события или новое правило, обычно
достаточно изменить конфиг.

## Сборка

Проект собирается через CMake. GoogleTest подключается через CMake
`FetchContent`.

```bash
cmake -S . -B build
cmake --build build
```

Исполняемый файл после сборки:

```bash
./build/minisiem
```

## Тесты

Тесты написаны на GoogleTest, собираются вместе с проектом и запускаются через
CTest из каталога сборки:

```bash
cd build
ctest --output-on-failure
```

Тестируется тот же код, который используется основным приложением: библиотека
`minisiem_core`.

## Запуск

```bash
./build/minisiem auth.log fail2ban.log
./build/minisiem auth.log --min-severity medium
./build/minisiem auth.log --json -o alerts.jsonl
./build/minisiem auth.log --csv -o alerts.csv
./build/minisiem auth.log --stats
./build/minisiem --list-rules
./build/minisiem - < auth.log
```

Поддерживаемые флаги:

- `-c/--config PATH` - путь к YAML-конфигу, по умолчанию `config.yaml`.
- `--json` - вывод алертов в JSON Lines.
- `--csv` - вывод алертов в CSV.
- `--stats` - печать статистики по событиям и алертам.
- `-o/--output PATH` - запись JSON/CSV в файл.
- `--min-severity LEVEL` - фильтр важности: `info`, `low`, `medium`, `high`,
  `critical`.
- `--list-rules` - показать правила и выйти.
- `--no-color` - отключить ANSI-цвета.

## Конфиг

Файл `config.yaml` содержит две секции: `patterns` и `rules`.

```yaml
patterns:
  ssh_failed: 'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)'

rules:
  - id: ssh_bruteforce
    title: SSH brute-force
    severity: high
    event: ssh_failed
    type: threshold
    group_by: ip
    threshold: 5
    message: '{count} неудачных входов по SSH с {ip}'
```

Типы правил:

- `match` - алерт на каждое событие. Можно добавить фильтр `where`.
- `threshold` - алерт, если число событий с одинаковым `group_by` не меньше
  `threshold`.

В `message` можно подставлять поля события и `{count}`.

## Структура проекта

- `include/minisiem.hpp` - публичные структуры и функции, документация Doxygen.
- `src/minisiem.cpp` - реализация парсинга, правил, вывода и статистики.
- `src/main.cpp` - консольный интерфейс и обработка исключений.
- `tests/test_minisiem.cpp` - GoogleTest-тесты.
- `config.yaml` - правила и регулярные выражения.
- `auth.log`, `fail2ban.log` - примеры входных данных.

## Ограничения

- `threshold` считается по всему входному набору без временного окна.
- YAML-парсер поддерживает простой формат, используемый в `config.yaml`.
- В регулярках поддерживаются именованные группы `(?P<name>...)`; при загрузке
  они преобразуются в C++ `std::regex`.
