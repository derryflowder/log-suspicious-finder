import re

import streamlit as st

from src.analyzer import analyze_line, export_results_json, summarize_findings

FINDING_LABELS = {
    "possible SQL injection": "Возможная SQL-инъекция",
    "possible XSS": "Возможный XSS (межсайтовый скриптинг)",
    "possible scanner probe": "Возможное сканирование",
    "HTTP client error (400)": "HTTP-ошибка клиента (400)",
    "HTTP client error (403)": "HTTP-ошибка клиента (403)",
    "HTTP client error (404)": "HTTP-ошибка клиента (404)",
}

def format_finding(finding: str) -> str:
    if finding in FINDING_LABELS:
        return FINDING_LABELS[finding]

    match = re.fullmatch(r"HTTP (client|server) error \((\d{3})\)", finding)

    if match:
        error_type, status_code = match.groups()
        category = "клиента" if error_type == "client" else "сервера"
        return f"HTTP-ошибка {category} ({status_code})"

    return finding

st.set_page_config(
    page_title="Log Suspicious Finder",
    page_icon="🔎",
    layout="wide",
)

st.title("🔎 Log Suspicious Finder")
st.write(
    "Загрузите веб-лог, чтобы найти потенциально подозрительные запросы "
    "и HTTP-ошибки."
)

with st.expander("Что делает этот инструмент?"):
    st.markdown(
        """
        - Ищет возможные SQL-инъекции и XSS.
        - Отмечает обращения к типичным путям сканеров.
        - Выявляет HTTP-ответы с кодами 4xx и 5xx.
        - Позволяет скачать результаты в формате JSON.

        **Важно:** найденные индикаторы требуют проверки и сами по себе
        не доказывают атаку.
        """
    )

uploaded_file = st.file_uploader(
    "Выберите файл веб-лога",
    type=["log", "txt"],
    help="Поддерживаются текстовые файлы с записями веб-сервера.",
)

if uploaded_file is not None:
    st.caption(f"Выбран файл: {uploaded_file.name}")

    if st.button("Анализировать лог", type="primary"):
        content = uploaded_file.getvalue().decode(
            "utf-8",
            errors="replace",
        )

        results = []

        for line_number, line in enumerate(content.splitlines(), start=1):
            findings = analyze_line(line)

            if findings:
                results.append((line_number, line, findings))

        st.session_state["analysis_results"] = results
        st.session_state["uploaded_filename"] = uploaded_file.name


if "analysis_results" in st.session_state:
    results = st.session_state["analysis_results"]
    summary = summarize_findings(results)

    st.divider()
    st.subheader("Результаты анализа")

    col1, col2 = st.columns(2)
    col1.metric("Подозрительные строки", len(results))
    col2.metric("Типы обнаруженных индикаторов", len(summary))

    if not results:
        st.success(
            "Подозрительных индикаторов не обнаружено. "
            "Это не гарантирует, что лог не содержит угроз."
        )
    else:
        st.subheader("Сводка")

        summary_rows = [
            {
                "Индикатор": format_finding(finding),
                "Количество": count,
            }
            for finding, count in sorted(summary.items())
        ]

        st.dataframe(
            summary_rows,
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Подробные результаты")

        detail_rows = [
            {
                "Строка": line_number,
                "Найденные индикаторы": ", ".join(
                    format_finding(finding)
                    for finding in findings
                ),
                "Запись лога": line,
            }
            for line_number, line, findings in results
        ]

        st.dataframe(
            detail_rows,
            use_container_width=True,
            hide_index=True,
        )

    json_data = export_results_json(results)

    st.download_button(
        label="Скачать результаты в JSON",
        data=json_data,
        file_name="analysis-results.json",
        mime="application/json",
    )
