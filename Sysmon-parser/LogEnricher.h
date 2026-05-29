#pragma once
#include "nlohmann/json.hpp"
#include <string>
#include <chrono>

/**
 * @namespace LogEnricher
 * @brief Модуль для формирования итогового JSON-объекта лога.
 */
namespace LogEnricher {

    /**
     * @brief Создает JSON-объект из данных Sysmon.
     * @param xmlData Строка с сырым XML-логом.
     * @return nlohmann::json Готовый JSON-объект.
     */
    inline nlohmann::json Enrich(const std::string& xmlData) {
        nlohmann::json j;

        j["timestamp"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        j["data"] = xmlData;

        return j;
    }
}