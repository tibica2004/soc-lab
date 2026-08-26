# Antares emite tool calls, dar nu consuma rezultate

TEST 1 - emitere: definit un tool nou (query_past_cases) doar in prompt,
in formatul din chat_template.jinja. Modelul l-a apelat corect: nume,
ambele argumente, uuid copiat exact, days=30 derivat din "past 30 days".
-> POATE emite tool calls pentru unelte nevazute la antrenament.

TEST 2 - consum: acelasi prompt, plus un <tool_response> cu rezultatul
(50 cazuri, 48 fals-pozitive). Modelul a cerut ACEEASI unealta din nou.
<think> spunea "Need to call query_past_cases to proceed" - ca si cum
n-ar fi vazut niciun raspuns.
Verificat cu formatul exact din inference/granite.py, inclusiv
_ASSISTANT_PREFILL = "<|start_of_role|>assistant<|end_of_role|><think>\n".
Acelasi rezultat.
-> NU integreaza rezultate de la unelte noi.

CONFIRMARE INDEPENDENTA: CLI-ul oficial are format_duplicate_tool_retry
cu mesajul "You already called these tools with these exact arguments.
Please try a different approach." Producatorul stia si a compensat in harness.

INTERPRETARE: pentru `terminal`, output-ul de shell e ceva ce modelul a
vazut de mii de ori in GRPO. Un obiect JSON de la o unealta necunoscuta nu e.
Emitatorul de tool calls e generalizabil; consumatorul nu.

CONSECINTA ARHITECTURALA: MCP nu are ce transporta. Bucla cerere-raspuns-
continuare nu functioneaza. Ramane arhitectura cu CONTEXT PRE-ADUS:
lookup-uri deterministe aduc datele, modelul le primeste in prompt.
Aceeasi concluzie la care a ajuns si echipa Elastic (agentii lor de
pattern si summarizer nu au unelte asignate).

LIMITARE: un singur tool, un singur format de raspuns. Nu exclude ca alt
format (ex. text simplu in loc de JSON) sa functioneze.
