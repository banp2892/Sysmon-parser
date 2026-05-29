#pragma once
#include <windows.h>
#include <string>
#include <variant>

/**
* @file Structures.h
* @brief В этом файле представленны все структуры, которые используются драйвером SystemMonitor для логирования данных
* Он используется, чтобы не засорять cpp-шный файл
*/

/**
 * @struct ID_1_SYSMONEVENT_CREATE_PROCESS
 * @brief Данные о создании процесса (ID 1).
 */
struct ID_1_SYSMONEVENT_CREATE_PROCESS {
    std::wstring RuleName;           ///< [RuleName] Имя правила Sysmon, вызвавшего событие
    std::wstring UtcTime;            ///< [UtcTime] Время создания процесса в формате UTC
    std::wstring ProcessGuid;        ///< [ProcessGuid] Уникальный GUID процесса в рамках Sysmon
    DWORD ProcessId;                 ///< [ProcessId] Идентификатор созданного процесса (PID)
    std::wstring Image;              ///< [Image] Полный путь к исполняемому файлу
    std::wstring FileVersion;        ///< [FileVersion] Версия файла из метаданных EXE
    std::wstring Description;        ///< [Description] Описание файла из ресурсов EXE
    std::wstring Product;            ///< [Product] Название продукта, к которому относится файл
    std::wstring Company;            ///< [Company] Название компании-производителя
    std::wstring OriginalFileName;   ///< [OriginalFileName] Исходное имя файла (даже если EXE переименован)
    std::wstring CommandLine;        ///< [CommandLine] Полная командная строка запуска
    std::wstring CurrentDirectory;   ///< [CurrentDirectory] Рабочая директория процесса
    std::wstring User;               ///< [User] Имя пользователя, запустившего процесс
    std::wstring LogonGuid;          ///< [LogonGuid] GUID сессии входа пользователя
    std::wstring LogonId;            ///< [LogonId] Идентификатор сессии входа (HexInt64)
    DWORD TerminalSessionId;         ///< [TerminalSessionId] ID терминальной сессии (RDP)
    std::wstring IntegrityLevel;     ///< [IntegrityLevel] Уровень целостности (Mandatory Integrity Control)
    std::wstring Hashes;             ///< [Hashes] Хеши файла (MD5, SHA256 и др.)
    std::wstring ParentProcessGuid;  ///< [ParentProcessGuid] GUID родительского процесса
    DWORD ParentProcessId;           ///< [ParentProcessId] PID родительского процесса
    std::wstring ParentImage;        ///< [ParentImage] Путь к исполняемому файлу родителя
    std::wstring ParentCommandLine;  ///< [ParentCommandLine] Командная строка родителя
    std::wstring ParentUser;         ///< [ParentUser] Имя пользователя родительского процесса
};

/**
 * @struct ID_2_SYSMONEVENT_FILE_TIME
 * @brief Данные об изменении времени создания файла (ID 2).
 */
struct ID_2_SYSMONEVENT_FILE_TIME {
    std::wstring RuleName;               ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;                ///< [UtcTime] Время события в формате UTC
    std::wstring ProcessGuid;            ///< [ProcessGuid] GUID процесса, изменившего время
    DWORD ProcessId;                     ///< [ProcessId] PID процесса, изменившего время
    std::wstring Image;                  ///< [Image] Путь к процессу, изменившему время
    std::wstring TargetFilename;         ///< [TargetFilename] Путь к файлу, время которого было изменено
    std::wstring CreationUtcTime;        ///< [CreationUtcTime] Новое время создания файла
    std::wstring PreviousCreationUtcTime; ///< [PreviousCreationUtcTime] Старое время создания файла
    std::wstring User;                   ///< [User] Пользователь, совершивший действие
};

/**
 * @struct ID_3_SYSMONEVENT_NETWORK_CONNECT
 * @brief Данные о сетевом соединении (ID 3).
 */
struct ID_3_SYSMONEVENT_NETWORK_CONNECT {
    std::wstring RuleName;           ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;            ///< [UtcTime] Время события в формате UTC
    std::wstring ProcessGuid;        ///< [ProcessGuid] GUID процесса, открывшего соединение
    DWORD ProcessId;                 ///< [ProcessId] PID процесса
    std::wstring Image;              ///< [Image] Путь к исполняемому файлу процесса
    std::wstring User;               ///< [User] Пользователь, от имени которого открыто соединение
    std::wstring Protocol;           ///< [Protocol] Протокол (tcp/udp)
    std::wstring Initiated;          ///< [Initiated] Было ли соединение инициировано локально (true/false)
    std::wstring SourceIsIpv6;       ///< [SourceIsIpv6] Является ли локальный адрес IPv6
    std::wstring SourceIp;           ///< [SourceIp] Локальный IP-адрес
    std::wstring SourceHostname;     ///< [SourceHostname] Локальное имя хоста
    DWORD SourcePort;                ///< [SourcePort] Локальный порт
    std::wstring SourcePortName;     ///< [SourcePortName] Сервисное имя локального порта
    std::wstring DestinationIsIpv6;  ///< [DestinationIsIpv6] Является ли удаленный адрес IPv6
    std::wstring DestinationIp;      ///< [DestinationIp] Удаленный IP-адрес
    std::wstring DestinationHostname; ///< [DestinationHostname] Удаленное доменное имя
    DWORD DestinationPort;           ///< [DestinationPort] Удаленный порт
    std::wstring DestinationPortName; ///< [DestinationPortName] Сервисное имя удаленного порта
};


/**
 * @struct ID_4_SYSMONEVENT_SERVICE_STATE_CHANGE
 * @brief Данные о изменении состояния службы Sysmon (ID 4).
 */
struct ID_4_SYSMONEVENT_SERVICE_STATE_CHANGE {
    std::wstring UtcTime;       ///< [UtcTime] Время изменения состояния в формате UTC
    std::wstring State;         ///< [State] Новое состояние службы (например, "Started" или "Stopped")
    std::wstring Version;       ///< [Version] Версия исполняемого файла Sysmon
    std::wstring SchemaVersion; ///< [SchemaVersion] Версия схемы конфигурации, используемая службой
};

/**
 * @struct ID_5_SYSMONEVENT_PROCESS_TERMINATE
 * @brief Данные о завершении процесса (ID 5).
 */
struct ID_5_SYSMONEVENT_PROCESS_TERMINATE {
    std::wstring RuleName;    ///< [RuleName] Имя правила, вызвавшего срабатывание
    std::wstring UtcTime;     ///< [UtcTime] Время завершения процесса в формате UTC
    std::wstring ProcessGuid; ///< [ProcessGuid] Уникальный идентификатор процесса Sysmon
    DWORD ProcessId;          ///< [ProcessId] Идентификатор процесса (PID)
    std::wstring Image;       ///< [Image] Полный путь к исполняемому файлу процесса
    std::wstring User;        ///< [User] Имя пользователя, в контексте которого работал процесс
};

/**
 * @struct ID_6_SYSMONEVENT_DRIVER_LOAD
 * @brief Данные о загрузке драйвера в систему (ID 6).
 */
struct ID_6_SYSMONEVENT_DRIVER_LOAD {
    std::wstring RuleName;        ///< [RuleName] Имя правила, вызвавшего срабатывание
    std::wstring UtcTime;         ///< [UtcTime] Время загрузки драйвера в формате UTC
    std::wstring ImageLoaded;     ///< [ImageLoaded] Путь к загруженному файлу драйвера (.sys)
    std::wstring Hashes;          ///< [Hashes] Хеши файла драйвера (MD5, SHA256 и др.)
    std::wstring Signed;          ///< [Signed] Статус подписи драйвера (true/false)
    std::wstring Signature;       ///< [Signature] Издатель подписи драйвера
    std::wstring SignatureStatus; ///< [SignatureStatus] Результат проверки подписи
};

/**
 * @struct ID_7_SYSMONEVENT_IMAGE_LOAD
 * @brief Данные о загрузке модуля/DLL в процесс (ID 7).
 */
struct ID_7_SYSMONEVENT_IMAGE_LOAD {
    std::wstring RuleName;        ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;         ///< [UtcTime] Время загрузки модуля в формате UTC
    std::wstring ProcessGuid;     ///< [ProcessGuid] GUID процесса, в который загружен модуль
    DWORD ProcessId;              ///< [ProcessId] PID процесса
    std::wstring Image;           ///< [Image] Путь к исполняемому файлу процесса
    std::wstring ImageLoaded;     ///< [ImageLoaded] Путь к загруженной DLL или исполняемому модулю
    std::wstring FileVersion;     ///< [FileVersion] Версия загруженного файла
    std::wstring Description;     ///< [Description] Описание загруженного файла
    std::wstring Product;         ///< [Product] Продукт, к которому относится файл
    std::wstring Company;         ///< [Company] Компания-производитель
    std::wstring OriginalFileName;///< [OriginalFileName] Исходное имя файла
    std::wstring Hashes;          ///< [Hashes] Хеши загруженного модуля
    std::wstring Signed;          ///< [Signed] Статус подписи (true/false)
    std::wstring Signature;       ///< [Signature] Издатель подписи
    std::wstring SignatureStatus; ///< [SignatureStatus] Результат проверки подписи
    std::wstring User;            ///< [User] Пользователь, в контексте которого загружен модуль
};

/**
 * @struct ID_8_SYSMONEVENT_CREATE_REMOTE_THREAD
 * @brief Данные о создании удаленного потока в другом процессе (ID 8).
 */
struct ID_8_SYSMONEVENT_CREATE_REMOTE_THREAD {
    std::wstring RuleName;         ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;          ///< [UtcTime] Время события в формате UTC
    std::wstring SourceProcessGuid;///< [SourceProcessGuid] GUID процесса-инициатора
    DWORD SourceProcessId;         ///< [SourceProcessId] PID процесса-инициатора
    std::wstring SourceImage;      ///< [SourceImage] Путь к исполняемому файлу инициатора
    std::wstring TargetProcessGuid;///< [TargetProcessGuid] GUID процесса-жертвы
    DWORD TargetProcessId;         ///< [TargetProcessId] PID процесса-жертвы
    std::wstring TargetImage;      ///< [TargetImage] Путь к исполняемому файлу жертвы
    DWORD NewThreadId;             ///< [NewThreadId] ID созданного потока
    std::wstring StartAddress;     ///< [StartAddress] Адрес памяти, с которого начнется выполнение
    std::wstring StartModule;      ///< [StartModule] Модуль, в котором находится стартовый адрес
    std::wstring StartFunction;    ///< [StartFunction] Имя функции, с которой начинается поток
    std::wstring SourceUser;       ///< [SourceUser] Пользователь процесса-инициатора
    std::wstring TargetUser;       ///< [TargetUser] Пользователь процесса-жертвы
};

/**
 * @struct ID_9_SYSMONEVENT_RAWACCESS_READ
 * @brief Данные о попытке прямого чтения диска (Raw Access) (ID 9).
 */
struct ID_9_SYSMONEVENT_RAWACCESS_READ {
    std::wstring RuleName;    ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;     ///< [UtcTime] Время события в формате UTC
    std::wstring ProcessGuid; ///< [ProcessGuid] GUID процесса, читающего диск напрямую
    DWORD ProcessId;          ///< [ProcessId] PID процесса
    std::wstring Image;       ///< [Image] Путь к исполняемому файлу процесса
    std::wstring Device;      ///< [Device] Путь к устройству
    std::wstring User;        ///< [User] Пользователь, совершивший чтение
};

/**
 * @struct ID_10_SYSMONEVENT_ACCESS_PROCESS
 * @brief Данные об открытии дескриптора (handle) другого процесса (ID 10).
 */
struct ID_10_SYSMONEVENT_ACCESS_PROCESS {
    std::wstring RuleName;          ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;           ///< [UtcTime] Время события в формате UTC
    std::wstring SourceProcessGUID; ///< [SourceProcessGUID] GUID процесса, запрашивающего доступ
    DWORD SourceProcessId;          ///< [SourceProcessId] PID процесса, запрашивающего доступ
    DWORD SourceThreadId;           ///< [SourceThreadId] ID потока, запрашивающего доступ
    std::wstring SourceImage;       ///< [SourceImage] Путь к исполняемому файлу инициатора
    std::wstring TargetProcessGUID; ///< [TargetProcessGUID] GUID процесса, к которому запрашивается доступ
    DWORD TargetProcessId;          ///< [TargetProcessId] PID процесса-цели
    std::wstring TargetImage;       ///< [TargetImage] Путь к исполняемому файлу цели
    std::wstring GrantedAccess;     ///< [GrantedAccess] Маска прав доступа (в HEX формате)
    std::wstring CallTrace;         ///< [CallTrace] Стек вызовов функций, приведший к открытию дескриптора
    std::wstring SourceUser;        ///< [SourceUser] Пользователь процесса-инициатора
    std::wstring TargetUser;        ///< [TargetUser] Пользователь процесса-цели
};

/**
 * @struct ID_11_SYSMONEVENT_FILE_CREATE
 * @brief Данные о создании нового файла или перезаписи существующего (ID 11).
 */
struct ID_11_SYSMONEVENT_FILE_CREATE {
    std::wstring RuleName;       ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;        ///< [UtcTime] Время создания файла в формате UTC
    std::wstring ProcessGuid;    ///< [ProcessGuid] GUID процесса, создавшего файл
    DWORD ProcessId;             ///< [ProcessId] PID процесса, создавшего файл
    std::wstring Image;          ///< [Image] Путь к исполняемому файлу процесса
    std::wstring TargetFilename; ///< [TargetFilename] Полный путь к созданному файлу
    std::wstring CreationUtcTime;///< [CreationUtcTime] Время создания файла (может отличаться от UtcTime события)
    std::wstring User;           ///< [User] Пользователь, создавший файл
};



/**
 * @struct ID_12_SYSMONEVENT_REG_KEY
 * @brief Данные о создании или удалении объекта реестра (ID 12).
 */
struct ID_12_SYSMONEVENT_REG_KEY {
    std::wstring RuleName;     ///< [RuleName] Имя правила Sysmon
    std::wstring EventType;    ///< [EventType] Тип события (CreateKey или DeleteKey)
    std::wstring UtcTime;      ///< [UtcTime] Время события в формате UTC
    std::wstring ProcessGuid;  ///< [ProcessGuid] GUID процесса, работающего с реестром
    DWORD ProcessId;           ///< [ProcessId] PID процесса
    std::wstring Image;        ///< [Image] Путь к исполняемому файлу процесса
    std::wstring TargetObject; ///< [TargetObject] Полный путь к ключу реестра
    std::wstring User;         ///< [User] Пользователь, совершивший действие
};

/**
 * @struct ID_13_SYSMONEVENT_REG_SETVALUE
 * @brief Данные об изменении или создании значения в реестре (ID 13).
 */
struct ID_13_SYSMONEVENT_REG_SETVALUE {
    std::wstring RuleName;     ///< [RuleName] Имя правила Sysmon
    std::wstring EventType;    ///< [EventType] Тип события (SetValue)
    std::wstring UtcTime;      ///< [UtcTime] Время записи в реестр в формате UTC
    std::wstring ProcessGuid;  ///< [ProcessGuid] GUID процесса, изменившего реестр
    DWORD ProcessId;           ///< [ProcessId] PID процесса
    std::wstring Image;        ///< [Image] Путь к исполняемому файлу процесса
    std::wstring TargetObject; ///< [TargetObject] Полный путь к параметру реестра
    std::wstring Details;      ///< [Details] Данные, которые были записаны в параметр
    std::wstring User;         ///< [User] Пользователь, совершивший действие
};

/**
 * @struct ID_14_SYSMONEVENT_REG_NAME
 * @brief Данные о переименовании ключа или значения реестра (ID 14).
 */
struct ID_14_SYSMONEVENT_REG_NAME {
    std::wstring RuleName;     ///< [RuleName] Имя правила Sysmon
    std::wstring EventType;    ///< [EventType] Тип события (RenameKey)
    std::wstring UtcTime;      ///< [UtcTime] Время события в формате UTC
    std::wstring ProcessGuid;  ///< [ProcessGuid] GUID процесса
    DWORD ProcessId;           ///< [ProcessId] PID процесса
    std::wstring Image;        ///< [Image] Путь к исполняемому файлу процесса
    std::wstring TargetObject; ///< [TargetObject] Исходный полный путь к объекту реестра
    std::wstring NewName;      ///< [NewName] Новое имя объекта реестра
    std::wstring User;         ///< [User] Пользователь, совершивший действие
};

/**
 * @struct ID_15_SYSMONEVENT_FILE_CREATE_STREAM_HASH
 * @brief Данные о создании альтернативного потока данных (ADS) (ID 15).
 */
struct ID_15_SYSMONEVENT_FILE_CREATE_STREAM_HASH {
    std::wstring RuleName;        ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;         ///< [UtcTime] Время создания потока в формате UTC
    std::wstring ProcessGuid;     ///< [ProcessGuid] GUID процесса, создавшего поток
    DWORD ProcessId;              ///< [ProcessId] PID процесса
    std::wstring Image;           ///< [Image] Путь к исполняемому файлу процесса
    std::wstring TargetFilename;  ///< [TargetFilename] Путь к основному файлу
    std::wstring CreationUtcTime; ///< [CreationUtcTime] Время создания файлового потока
    std::wstring Hash;            ///< [Hash] Полный хеш содержимого потока
    std::wstring Contents;        ///< [Contents] Текстовое содержимое потока (если применимо)
    std::wstring User;            ///< [User] Пользователь, создавший поток
};

/**
 * @struct ID_16_SYSMONEVENT_SERVICE_CONFIGURATION_CHANGE
 * @brief Данные об изменении конфигурации Sysmon (ID 16).
 */
struct ID_16_SYSMONEVENT_SERVICE_CONFIGURATION_CHANGE {
    std::wstring UtcTime;               ///< [UtcTime] Время изменения конфигурации в формате UTC
    std::wstring Configuration;         ///< [Configuration] Описание или путь к примененному файлу конфигурации
    std::wstring ConfigurationFileHash; ///< [ConfigurationFileHash] Хеш-сумма файла конфигурации
};

/**
 * @struct ID_17_SYSMONEVENT_CREATE_NAMEDPIPE
 * @brief Данные о создании именованного канала (Named Pipe) (ID 17).
 */
struct ID_17_SYSMONEVENT_CREATE_NAMEDPIPE {
    std::wstring RuleName;    ///< [RuleName] Имя правила Sysmon
    std::wstring EventType;   ///< [EventType] Тип события (CreatePipe)
    std::wstring UtcTime;     ///< [UtcTime] Время создания канала в формате UTC
    std::wstring ProcessGuid; ///< [ProcessGuid] GUID процесса, создавшего канал
    DWORD ProcessId;          ///< [ProcessId] PID процесса, создавшего канал
    std::wstring PipeName;    ///< [PipeName] Имя созданного канала
    std::wstring Image;       ///< [Image] Полный путь к исполняемому файлу процесса
    std::wstring User;        ///< [User] Пользователь, в контексте которого создан канал
};

/**
 * @struct ID_18_SYSMONEVENT_CONNECT_NAMEDPIPE
 * @brief Данные о подключении к именованному каналу (ID 18).
 */
struct ID_18_SYSMONEVENT_CONNECT_NAMEDPIPE {
    std::wstring RuleName;    ///< [RuleName] Имя правила Sysmon
    std::wstring EventType;   ///< [EventType] Тип события (ConnectPipe)
    std::wstring UtcTime;     ///< [UtcTime] Время подключения в формате UTC
    std::wstring ProcessGuid; ///< [ProcessGuid] GUID процесса, подключившегося к каналу
    DWORD ProcessId;          ///< [ProcessId] PID процесса, подключившегося к каналу
    std::wstring PipeName;    ///< [PipeName] Имя канала, к которому выполнено подключение
    std::wstring Image;       ///< [Image] Полный путь к исполняемому файлу процесса
    std::wstring User;        ///< [User] Пользователь, совершивший подключение
};

/**
 * @struct ID_19_SYSMONEVENT_WMI_FILTER
 * @brief Данные о регистрации фильтра событий WMI (ID 19).
 */
struct ID_19_SYSMONEVENT_WMI_FILTER {
    std::wstring RuleName;       ///< [RuleName] Имя правила Sysmon
    std::wstring EventType;      ///< [EventType] Тип события (WmiEventFilter activity detected)
    std::wstring UtcTime;        ///< [UtcTime] Время регистрации фильтра в формате UTC
    std::wstring Operation;      ///< [Operation] Операция (Created, Deleted, Modified)
    std::wstring User;           ///< [User] Пользователь, создавший фильтр
    std::wstring EventNamespace; ///< [EventNamespace] Пространство имен WMI 
    std::wstring Name;           ///< [Name] Имя созданного фильтра
    std::wstring Query;          ///< [Query] WQL-запрос, который описывает условие
};

/**
 * @struct ID_20_SYSMONEVENT_WMI_CONSUMER
 * @brief Данные о регистрации потребителя событий WMI (ID 20).
 */
struct ID_20_SYSMONEVENT_WMI_CONSUMER {
    std::wstring RuleName;    ///< [RuleName] Имя правила Sysmon
    std::wstring EventType;   ///< [EventType] Тип события (WmiEventConsumer activity detected)
    std::wstring UtcTime;     ///< [UtcTime] Время регистрации потребителя в формате UTC
    std::wstring Operation;   ///< [Operation] Операция (Created, Deleted, Modified)
    std::wstring User;        ///< [User] Пользователь, создавший потребителя
    std::wstring Name;        ///< [Name] Имя потребителя
    std::wstring Type;        ///< [Type] Тип (CommandLineEventConsumer или ScriptingEngineConsumer)
    std::wstring Destination; ///< [Destination] Путь к скрипту или командная строка, которая будет выполнена
};

/**
 * @struct ID_21_SYSMONEVENT_WMI_BINDING
 * @brief Данные о связывании фильтра и потребителя WMI (ID 21).
 */
struct ID_21_SYSMONEVENT_WMI_BINDING {
    std::wstring RuleName;  ///< [RuleName] Имя правила Sysmon
    std::wstring EventType; ///< [EventType] Тип события (WmiEventConsumerToFilter activity detected)
    std::wstring UtcTime;   ///< [UtcTime] Время создания связи в формате UTC
    std::wstring Operation; ///< [Operation] Операция (Created, Deleted)
    std::wstring User;      ///< [User] Пользователь, создавший связь
    std::wstring Consumer;  ///< [Consumer] Путь к потребителю
    std::wstring Filter;    ///< [Filter] Путь к фильтру
};

/**
 * @struct ID_22_SYSMONEVENT_DNS_QUERY
 * @brief Данные о DNS-запросе (ID 22).
 */
struct ID_22_SYSMONEVENT_DNS_QUERY {
    std::wstring RuleName;     ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;      ///< [UtcTime] Время запроса в формате UTC
    std::wstring ProcessGuid;  ///< [ProcessGuid] GUID процесса, инициировавшего запрос
    DWORD ProcessId;           ///< [ProcessId] PID процесса
    std::wstring QueryName;    ///< [QueryName] Запрашиваемое доменное имя
    std::wstring QueryStatus;  ///< [QueryStatus] Статус ответа DNS (0 — успех)
    std::wstring QueryResults; ///< [QueryResults] IP-адреса, возвращенные DNS-сервером
    std::wstring Image;        ///< [Image] Полный путь к исполняемому файлу процесса
    std::wstring User;         ///< [User] Пользователь, совершивший запрос
};

/**
 * @struct ID_23_SYSMONEVENT_FILE_DELETE
 * @brief Данные об удалении файла, который был заархивирован Sysmon (ID 23).
 */
struct ID_23_SYSMONEVENT_FILE_DELETE {
    std::wstring RuleName;       ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;        ///< [UtcTime] Время удаления в формате UTC
    std::wstring ProcessGuid;    ///< [ProcessGuid] GUID процесса, удалившего файл
    DWORD ProcessId;             ///< [ProcessId] PID процесса
    std::wstring User;           ///< [User] Пользователь, удаливший файл
    std::wstring Image;          ///< [Image] Полный путь к исполняемому файлу процесса
    std::wstring TargetFilename; ///< [TargetFilename] Путь к удаленному файлу
    std::wstring Hashes;          ///< [Hashes] Хеши удаленного файла
    std::wstring IsExecutable;   ///< [IsExecutable] Был ли файл исполняемым (true/false)
    std::wstring Archived;       ///< [Archived] Путь к копии файла в архиве Sysmon
};

/**
 * @struct ID_24_SYSMONEVENT_CLIPBOARD
 * @brief Данные об изменении содержимого буфера обмена (ID 24).
 */
struct ID_24_SYSMONEVENT_CLIPBOARD {
    std::wstring RuleName;    ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;     ///< [UtcTime] Время события в формате UTC
    std::wstring ProcessGuid; ///< [ProcessGuid] GUID процесса, записавшего данные в буфер
    DWORD ProcessId;          ///< [ProcessId] PID процесса
    std::wstring Image;       ///< [Image] Полный путь к исполняемому файлу процесса
    DWORD Session;            ///< [Session] Номер пользовательской сессии
    std::wstring ClientInfo;  ///< [ClientInfo] Информация о клиенте (актуально для RDP)
    std::wstring Hashes;      ///< [Hashes] Хеш данных, попавших в буфер обмена
    std::wstring Archived;    ///< [Archived] Статус архивации содержимого
    std::wstring User;        ///< [User] Пользователь, владеющий процессом
};

/**
 * @struct ID_25_SYSMONEVENT_PROCESS_IMAGE_TAMPERING
 * @brief Данные о попытке подмены образа процесса в памяти (ID 25).
 */
struct ID_25_SYSMONEVENT_PROCESS_IMAGE_TAMPERING {
    std::wstring RuleName;    ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;     ///< [UtcTime] Время события в формате UTC
    std::wstring ProcessGuid; ///< [ProcessGuid] GUID процесса, подвергшегося модификации
    DWORD ProcessId;          ///< [ProcessId] PID процесса
    std::wstring Image;       ///< [Image] Полный путь к исполняемому файлу процесса
    std::wstring Type;        ///< [Type] Тип обнаруженной манипуляции
    std::wstring User;        ///< [User] Пользователь, владеющий процессом
};

/**
 * @struct ID_26_SYSMONEVENT_FILE_DELETE_DETECTED
 * @brief Данные об удалении файла без его архивации (ID 26).
 */
struct ID_26_SYSMONEVENT_FILE_DELETE_DETECTED {
    std::wstring RuleName;       ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;        ///< [UtcTime] Время удаления в формате UTC
    std::wstring ProcessGuid;    ///< [ProcessGuid] GUID процесса, удалившего файл
    DWORD ProcessId;             ///< [ProcessId] PID процесса
    std::wstring User;           ///< [User] Пользователь, удаливший файл
    std::wstring Image;          ///< [Image] Путь к исполняемому файлу процесса
    std::wstring TargetFilename; ///< [TargetFilename] Путь к удаленному файлу
    std::wstring Hashes;          ///< [Hashes] Хеши удаленного файла
    std::wstring IsExecutable;   ///< [IsExecutable] Являлся ли файл исполняемым (Boolean)
};

/**
 * @struct ID_27_SYSMONEVENT_FILE_BLOCK_EXE
 * @brief Данные о заблокированной попытке создания исполняемого файла (ID 27).
 */
struct ID_27_SYSMONEVENT_FILE_BLOCK_EXE {
    std::wstring RuleName;       ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;        ///< [UtcTime] Время попытки записи в формате UTC
    std::wstring ProcessGuid;    ///< [ProcessGuid] GUID процесса, пытавшегося создать файл
    DWORD ProcessId;             ///< [ProcessId] PID процесса
    std::wstring User;           ///< [User] Пользователь, совершивший попытку
    std::wstring Image;          ///< [Image] Путь к исполняемому файлу процесса
    std::wstring TargetFilename; ///< [TargetFilename] Путь, по которому файл был заблокирован
    std::wstring Hashes;          ///< [Hashes] Хеши заблокированного файла
};

/**
 * @struct ID_28_SYSMONEVENT_FILE_BLOCK_SHREDDING
 * @brief Данные о блокировке попытки уничтожения файла (shredding) (ID 28).
 */
struct ID_28_SYSMONEVENT_FILE_BLOCK_SHREDDING {
    std::wstring RuleName;       ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;        ///< [UtcTime] Время попытки в формате UTC
    std::wstring ProcessGuid;    ///< [ProcessGuid] GUID процесса, пытавшегося затереть файл
    DWORD ProcessId;             ///< [ProcessId] PID процесса
    std::wstring User;           ///< [User] Пользователь, запустивший процесс
    std::wstring Image;          ///< [Image] Путь к исполняемому файлу процесса-шреддера
    std::wstring TargetFilename; ///< [TargetFilename] Путь к файлу, который пытались уничтожить
    std::wstring Hashes;          ///< [Hashes] Хеши защищаемого файла
    std::wstring IsExecutable;   ///< [IsExecutable] Является ли защищаемый файл исполняемым
};

/**
 * @struct ID_29_SYSMONEVENT_FILE_EXE_DETECTED
 * @brief Данные об обнаружении записи нового исполняемого файла на диск (ID 29).
 */
struct ID_29_SYSMONEVENT_FILE_EXE_DETECTED {
    std::wstring RuleName;       ///< [RuleName] Имя правила Sysmon
    std::wstring UtcTime;        ///< [UtcTime] Время обнаружения в формате UTC
    std::wstring ProcessGuid;    ///< [ProcessGuid] GUID процесса, создавшего EXE
    DWORD ProcessId;             ///< [ProcessId] PID процесса
    std::wstring User;           ///< [User] Пользователь, создавший файл
    std::wstring Image;          ///< [Image] Путь к процессу, который записал файл
    std::wstring TargetFilename; ///< [TargetFilename] Полный путь к новому исполняемому файлу
    std::wstring Hashes;          ///< [Hashes] Хеши нового файла
};




/**
 * @struct SysmonEvent
 * @brief Универсальный транспортный контейнер для всех событий Sysmon.
 */
struct SysmonEvent {
    long long timestamp;        ///< Время события (из заголовка ETW/SystemTime)
    USHORT eventId;                ///< ID события (1, 2, 3 ... 29)
    std::wstring timestamp_wstring; ///< Время в формате wstring

    /**
     * @brief Объединение всех возможных структур данных событий.
     * variant гарантирует, что размер контейнера будет равен размеру самой большой структуры + индекс.
     */
    std::variant <
        std::monostate, // Для обработки неопознанных ID
        ID_1_SYSMONEVENT_CREATE_PROCESS,
        ID_2_SYSMONEVENT_FILE_TIME,
        ID_3_SYSMONEVENT_NETWORK_CONNECT,
        ID_4_SYSMONEVENT_SERVICE_STATE_CHANGE,
        ID_5_SYSMONEVENT_PROCESS_TERMINATE,
        ID_6_SYSMONEVENT_DRIVER_LOAD,
        ID_7_SYSMONEVENT_IMAGE_LOAD,
        ID_8_SYSMONEVENT_CREATE_REMOTE_THREAD,
        ID_9_SYSMONEVENT_RAWACCESS_READ,
        ID_10_SYSMONEVENT_ACCESS_PROCESS,
        ID_11_SYSMONEVENT_FILE_CREATE,
        ID_12_SYSMONEVENT_REG_KEY,
        ID_13_SYSMONEVENT_REG_SETVALUE,
        ID_14_SYSMONEVENT_REG_NAME,
        ID_15_SYSMONEVENT_FILE_CREATE_STREAM_HASH,
        ID_16_SYSMONEVENT_SERVICE_CONFIGURATION_CHANGE,
        ID_17_SYSMONEVENT_CREATE_NAMEDPIPE,
        ID_18_SYSMONEVENT_CONNECT_NAMEDPIPE,
        ID_19_SYSMONEVENT_WMI_FILTER,
        ID_20_SYSMONEVENT_WMI_CONSUMER,
        ID_21_SYSMONEVENT_WMI_BINDING,
        ID_22_SYSMONEVENT_DNS_QUERY,
        ID_23_SYSMONEVENT_FILE_DELETE,
        ID_24_SYSMONEVENT_CLIPBOARD,
        ID_25_SYSMONEVENT_PROCESS_IMAGE_TAMPERING,
        ID_26_SYSMONEVENT_FILE_DELETE_DETECTED,
        ID_27_SYSMONEVENT_FILE_BLOCK_EXE,
        ID_28_SYSMONEVENT_FILE_BLOCK_SHREDDING,
        ID_29_SYSMONEVENT_FILE_EXE_DETECTED
    > eventData;
};