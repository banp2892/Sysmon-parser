#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace Metrics {
    // Метрика CPU (подготовлена ранее)
    float GetCpuUsage(float current) { return current; }

    // Метрика: вычисление энтропии строки (можно передать прямо сюда)
    double GetEntropy(const std::string& input) {
        // ... ваш код энтропии ...
        return 0.0;
    }

    // Метрика: наличие подозрительных символов
    float GetSpecialCharDensity(const std::string& input) {
        // ... ваш код ...
        return 0.0f;
    }
}