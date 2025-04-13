/*
 * ASD (AnmiTali Software Distribution) asr (as root)
 * 
 * A program to execute commands with root privileges,
 * independent from sudo.
 * 
 * Author: AnmiTaliDev
 * License: Apache 2.0
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <pwd.h>
 #include <grp.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <sys/wait.h>
 #include <errno.h>
 #include <shadow.h>
 #include <crypt.h>
 #include <fcntl.h>
 #include <time.h>
 
 #define VERSION "1.0.0"
 #define PROGRAM_NAME "asr"
 #define CONFIG_FILE "/etc/asr.conf"
 #define LOG_FILE "/var/log/asr.log"
 #define MAX_LINE_LENGTH 1024
 #define MAX_PATH_LENGTH 256
 #define MAX_TIME_STRING 128
 
 // Структура для хранения информации о пользователях
 typedef struct {
     char username[256];
     int can_execute_all;
     char **allowed_commands;
     int num_allowed_commands;
 } UserInfo;
 
 // Глобальные переменные для хранения конфигурации
 UserInfo *authorized_users = NULL;
 int num_authorized_users = 0;
 
 void print_usage(void) {
     printf("ASD (AnmiTali Software Distribution) asr (as root) version %s\n", VERSION);
     printf("Usage: %s [OPTIONS] COMMAND [ARGS]\n\n", PROGRAM_NAME);
     printf("Options:\n");
     printf("  -h, --help     Display this help message and exit\n");
     printf("  -v, --version  Display version information and exit\n");
     printf("  -l, --list     List allowed commands for current user\n");
     printf("  -e, --edit     Edit configuration file (requires root)\n");
     printf("\n");
     printf("Run a command with root privileges.\n");
 }
 
 void print_version(void) {
     printf("ASD (AnmiTali Software Distribution) asr (as root) version %s\n", VERSION);
     printf("Licensed under Apache 2.0\n");
     printf("Author: AnmiTaliDev\n");
 }
 
 // Запись в лог-файл
 void log_execution(const char *username, const char *command, int success) {
     FILE *log_file = fopen(LOG_FILE, "a");
     if (!log_file) {
         perror("Cannot open log file");
         return;
     }
     
     time_t now = time(NULL);
     char time_str[MAX_TIME_STRING];
     struct tm *tm_info = localtime(&now);
     strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
     
     fprintf(log_file, "[%s] User: %s, Command: %s, Status: %s\n", 
             time_str, username, command, success ? "SUCCESS" : "FAILED");
     
     fclose(log_file);
 }
 
 // Загрузка конфигурации из файла
 int load_configuration(void) {
     FILE *config = fopen(CONFIG_FILE, "r");
     if (!config) {
         // Если файл не существует, создаем его с разрешениями только для root
         if (errno == ENOENT && geteuid() == 0) {
             config = fopen(CONFIG_FILE, "w");
             if (config) {
                 fprintf(config, "# ASR Configuration File\n");
                 fprintf(config, "# Format: username:all|cmd1,cmd2,cmd3\n");
                 fprintf(config, "# Example: john:all\n");
                 fprintf(config, "# Example: jane:/bin/ls,/usr/bin/apt\n");
                 fclose(config);
                 chmod(CONFIG_FILE, 0600); // Только root может читать и писать
                 printf("Created empty configuration file: %s\n", CONFIG_FILE);
                 return 0;
             } else {
                 perror("Cannot create configuration file");
                 return 0;
             }
         }
         perror("Cannot open configuration file");
         return 0;
     }
     
     // Сначала подсчитаем количество строк (пользователей)
     char line[MAX_LINE_LENGTH];
     num_authorized_users = 0;
     
     while (fgets(line, sizeof(line), config)) {
         // Пропускаем комментарии и пустые строки
         if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
             continue;
         }
         num_authorized_users++;
     }
     
     // Выделяем память под массив пользователей
     authorized_users = calloc(num_authorized_users, sizeof(UserInfo));
     if (!authorized_users) {
         perror("Memory allocation failed");
         fclose(config);
         return 0;
     }
     
     // Сбрасываем указатель файла в начало
     rewind(config);
     
     int user_index = 0;
     
     while (fgets(line, sizeof(line), config) && user_index < num_authorized_users) {
         // Пропускаем комментарии и пустые строки
         if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
             continue;
         }
         
         // Удаляем символ новой строки
         line[strcspn(line, "\n")] = '\0';
         
         // Формат строки: username:all|cmd1,cmd2,cmd3
         char *username = strtok(line, ":");
         char *commands = strtok(NULL, ":");
         
         if (!username || !commands) {
             fprintf(stderr, "Invalid line in config: %s\n", line);
             continue;
         }
         
         strncpy(authorized_users[user_index].username, username, sizeof(authorized_users[user_index].username) - 1);
         
         // Проверяем, может ли пользователь выполнять все команды
         if (strcmp(commands, "all") == 0) {
             authorized_users[user_index].can_execute_all = 1;
             authorized_users[user_index].allowed_commands = NULL;
             authorized_users[user_index].num_allowed_commands = 0;
         } else {
             authorized_users[user_index].can_execute_all = 0;
             
             // Подсчитываем количество команд
             int num_commands = 1;
             for (char *p = commands; *p; p++) {
                 if (*p == ',') {
                     num_commands++;
                 }
             }
             
             // Выделяем память под массив команд
             authorized_users[user_index].allowed_commands = calloc(num_commands, sizeof(char *));
             if (!authorized_users[user_index].allowed_commands) {
                 perror("Memory allocation failed");
                 continue;
             }
             
             authorized_users[user_index].num_allowed_commands = num_commands;
             
             // Заполняем массив команд
             char *cmd = strtok(commands, ",");
             int cmd_index = 0;
             
             while (cmd && cmd_index < num_commands) {
                 authorized_users[user_index].allowed_commands[cmd_index] = strdup(cmd);
                 cmd = strtok(NULL, ",");
                 cmd_index++;
             }
         }
         
         user_index++;
     }
     
     fclose(config);
     return 1;
 }
 
 // Освобождение памяти
 void free_configuration(void) {
     for (int i = 0; i < num_authorized_users; i++) {
         if (!authorized_users[i].can_execute_all) {
             for (int j = 0; j < authorized_users[i].num_allowed_commands; j++) {
                 free(authorized_users[i].allowed_commands[j]);
             }
             free(authorized_users[i].allowed_commands);
         }
     }
     free(authorized_users);
 }
 
 // Проверка авторизации пользователя
 int is_user_authorized(const char *username, const char *command) {
     if (!authorized_users) {
         return 0;
     }
     
     for (int i = 0; i < num_authorized_users; i++) {
         if (strcmp(authorized_users[i].username, username) == 0) {
             // Пользователь найден, проверяем его права
             if (authorized_users[i].can_execute_all) {
                 return 1; // Может выполнять любые команды
             }
             
             // Проверяем, есть ли команда в списке разрешенных
             for (int j = 0; j < authorized_users[i].num_allowed_commands; j++) {
                 if (strcmp(authorized_users[i].allowed_commands[j], command) == 0) {
                     return 1;
                 }
             }
             
             // Команда не найдена в списке разрешенных
             return 0;
         }
     }
     
     // Пользователь не найден
     return 0;
 }
 
 // Вывод списка разрешенных команд для текущего пользователя
 void list_allowed_commands(const char *username) {
     if (!authorized_users) {
         printf("No configuration loaded.\n");
         return;
     }
     
     for (int i = 0; i < num_authorized_users; i++) {
         if (strcmp(authorized_users[i].username, username) == 0) {
             printf("Allowed commands for user %s:\n", username);
             
             if (authorized_users[i].can_execute_all) {
                 printf("All commands\n");
             } else {
                 for (int j = 0; j < authorized_users[i].num_allowed_commands; j++) {
                     printf("- %s\n", authorized_users[i].allowed_commands[j]);
                 }
             }
             
             return;
         }
     }
     
     printf("User %s is not in the asr configuration.\n", username);
 }
 
 // Проверка аутентификации пользователя
 int authenticate_user(const char *username) {
     char password[256];
     struct spwd *spw;
     char *encrypted, *correct;
     
     spw = getspnam(username);
     if (!spw) {
         // Если не можем получить запись из shadow, не можем аутентифицировать
         perror("Cannot get password information");
         return 0;
     }
     
     correct = spw->sp_pwdp;
     
     printf("Hey, %s! Please enter your user password for asr: ", username);
     
     // Отключаем эхо для ввода пароля
     system("stty -echo");
     
     if (fgets(password, sizeof(password), stdin) == NULL) {
         system("stty echo");
         printf("\n");
         return 0;
     }
     
     // Удаляем символ новой строки
     password[strcspn(password, "\n")] = '\0';
     
     // Включаем эхо обратно
     system("stty echo");
     printf("\n");
     
     // Шифруем введенный пароль и сравниваем с правильным
     encrypted = crypt(password, correct);
     if (encrypted == NULL) {
         perror("crypt failed");
         return 0;
     }
     
     return strcmp(encrypted, correct) == 0;
 }
 
 // Открытие редактора для изменения конфигурационного файла
 void edit_configuration(void) {
     if (geteuid() != 0) {
         fprintf(stderr, "Error: Only root can edit the configuration file\n");
         return;
     }
     
     // Используем EDITOR из переменных окружения или vim/nano по умолчанию
     char *editor = getenv("EDITOR");
     if (!editor) {
         // Проверяем наличие vim или nano
         if (access("/usr/bin/vim", X_OK) == 0) {
             editor = "/usr/bin/vim";
         } else if (access("/usr/bin/nano", X_OK) == 0) {
             editor = "/usr/bin/nano";
         } else {
             fprintf(stderr, "Error: No text editor found. Set EDITOR environment variable.\n");
             return;
         }
     }
     
     char command[MAX_PATH_LENGTH * 2];
     snprintf(command, sizeof(command), "%s %s", editor, CONFIG_FILE);
     
     system(command);
 }
 
 // Выполнение команды с привилегиями root
 int execute_command_as_root(char **args) {
     pid_t child_pid;
     int status;
 
     child_pid = fork();
     
     if (child_pid < 0) {
         perror("Fork failed");
         return 1;
     } else if (child_pid == 0) {
         // Дочерний процесс
         // Должны быть setuid root для этого
         if (setuid(0) != 0) {
             perror("setuid failed");
             exit(EXIT_FAILURE);
         }
         
         // Устанавливаем дополнительные группы root
         gid_t root_gid = 0;
         if (setgid(root_gid) != 0) {
             perror("setgid failed");
             exit(EXIT_FAILURE);
         }
         
         // Получаем все группы root
         struct passwd *root_pwd = getpwnam("root");
         if (root_pwd) {
             int ngroups = 0;
             getgrouplist("root", root_pwd->pw_gid, NULL, &ngroups);
             
             if (ngroups > 0) {
                 gid_t *groups = malloc(ngroups * sizeof(gid_t));
                 if (groups) {
                     if (getgrouplist("root", root_pwd->pw_gid, groups, &ngroups) != -1) {
                         if (setgroups(ngroups, groups) != 0) {
                             perror("setgroups failed");
                         }
                     }
                     free(groups);
                 }
             }
         }
         
         execvp(args[0], args);
         
         // Если execvp вернул управление, значит произошла ошибка
         perror("Command execution failed");
         exit(EXIT_FAILURE);
     } else {
         // Родительский процесс
         waitpid(child_pid, &status, 0);
         
         if (WIFEXITED(status)) {
             return WEXITSTATUS(status);
         } else {
             return 1;
         }
     }
 }
 
 int main(int argc, char *argv[]) {
     // Разбор аргументов командной строки
     if (argc < 2) {
         print_usage();
         return EXIT_FAILURE;
     }
     
     if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
         print_usage();
         return EXIT_SUCCESS;
     }
     
     if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
         print_version();
         return EXIT_SUCCESS;
     }
     
     if (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "--edit") == 0) {
         edit_configuration();
         return EXIT_SUCCESS;
     }
     
     // Проверяем, установлен ли setuid бит
     if (geteuid() != 0) {
         fprintf(stderr, "Error: %s is not set up with setuid root permissions\n", PROGRAM_NAME);
         fprintf(stderr, "Please install with: sudo chown root:root %s && sudo chmod 4755 %s\n", 
                 PROGRAM_NAME, PROGRAM_NAME);
         return EXIT_FAILURE;
     }
     
     // Загружаем конфигурацию
     if (!load_configuration()) {
         fprintf(stderr, "Warning: Failed to load configuration\n");
     }
     
     // Получаем имя пользователя
     struct passwd *pw = getpwuid(getuid());
     if (!pw) {
         perror("Cannot get user information");
         free_configuration();
         return EXIT_FAILURE;
     }
     
     char *username = pw->pw_name;
     
     // Если пользователь запросил список команд
     if (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--list") == 0) {
         list_allowed_commands(username);
         free_configuration();
         return EXIT_SUCCESS;
     }
     
     // Полный путь к команде для проверки авторизации
     char command_path[MAX_PATH_LENGTH];
     if (argv[1][0] == '/') {
         // Уже абсолютный путь
         strncpy(command_path, argv[1], sizeof(command_path) - 1);
     } else {
         // Находим полный путь к команде
         char *path_env = getenv("PATH");
         if (!path_env) {
             path_env = "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$HOME/.local/bin";
         }
         
         char *path_copy = strdup(path_env);
         char *path_token = strtok(path_copy, ":");
         int found = 0;
         
         while (path_token && !found) {
             snprintf(command_path, sizeof(command_path), "%s/%s", path_token, argv[1]);
             if (access(command_path, X_OK) == 0) {
                 found = 1;
             } else {
                 path_token = strtok(NULL, ":");
             }
         }
         
         free(path_copy);
         
         if (!found) {
             fprintf(stderr, "Error: Command not found: %s\n", argv[1]);
             free_configuration();
             return EXIT_FAILURE;
         }
     }
     
     // Проверяем авторизацию пользователя
     if (!is_user_authorized(username, command_path)) {
         fprintf(stderr, "Error: User %s is not authorized to run command: %s\n", username, command_path);
         log_execution(username, command_path, 0);
         free_configuration();
         return EXIT_FAILURE;
     }
     
     // Аутентифицируем пользователя
     if (!authenticate_user(username)) {
         fprintf(stderr, "Error: Authentication failed\n");
         log_execution(username, command_path, 0);
         free_configuration();
         return EXIT_FAILURE;
     }
     
     // Выполняем команду с правами root
     int result = execute_command_as_root(&argv[1]);
     
     // Записываем в лог
     log_execution(username, command_path, result == 0);
     
     // Освобождаем память
     free_configuration();
     
     return result;
 }