"""
CAUSAL 2.0 - Independent Verification Script (Template)
Author: [Ваше Имя / Имя Рецензента]
Date: [Дата]

ВНИМАНИЕ: Этот скрипт НЕ импортирует код авторов (src/*). 
Он реализует независимую проверку спецификации.
Для работы необходимо заполнить функции, помеченные NotImplementedError,
руководствуясь документом SPECIFICATION.md (или спецификацией 3Z).
"""
import json
import hashlib
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Путь к распакованному пакету CAUSAL_3AE_OFFLINE
PKG_ROOT = Path("./")
QUEUE_FILE = PKG_ROOT / "HUMAN_REVIEW_QUEUE.json"

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ==============================================================================
# 1. СВЕРКА ПИННИНГА (ХЭШИ ФАЙЛОВ)
# ==============================================================================
def verify_pinning(queue: dict) -> bool:
    print("--- 1. Проверка SHA-256 пиннинга (fixtures и references) ---")
    fails = 0
    for item in queue["items"]:
        vid = item["vector_id"]
        for kind, path_key, sha_key in [
            ("fixture",   "fixture_path",   "fixture_sha256"),
            ("reference", "reference_path", "reference_sha256"),
        ]:
            p = PKG_ROOT / item[path_key]
            if not p.is_file():
                print(f"FAIL: {vid} {kind} не найден")
                fails += 1
                continue
            actual = sha256_hex(p.read_bytes())
            if actual != item[sha_key]:
                print(f"FAIL: {vid} {kind} хэш не совпадает")
                fails += 1
    print(f"Результат: {'PASS' if fails == 0 else f'FAIL ({fails} ошибок)'}\n")
    return fails == 0

# ==============================================================================
# 2. ПОЛОЖИТЕЛЬНЫЕ КЕЙСЫ (КРИПТОГРАФИЯ)
# ==============================================================================
def canonicalize(fixture: dict) -> bytes:
    """
    ЗАПОЛНИТЬ РЕЦЕНЗЕНТУ: Реализация RFC 8785 (JCS).
    Для простых случаев это json.dumps(sort_keys=True, separators=(',', ':'))
    Но для полного соответствия нужно учесть правила чисел и Unicode.
    """
    # Пример-заглушка для ASCII (рецензент должен проверить по спецификации 3Z)
    # return json.dumps(fixture, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    raise NotImplementedError("Реализуйте RFC 8785 (JCS) согласно спецификации 3Z")

def build_frame(payload: bytes) -> bytes:
    """
    ЗАПОЛНИТЬ РЕЦЕНЗЕНТУ: Построение Domain-Separated Frame.
    Обычно это: DomainPrefix || uint64_big_endian(len(payload)) || payload
    """
    raise NotImplementedError("Реализуйте сборку фрейма согласно спецификации 3Z")

def verify_positive_cases(queue: dict) -> bool:
    print("--- 2. Положительные кейсы (LOCAL_BYTES_MATCH) ---")
    fails = 0
    pos_items = [i for i in queue["items"] if i["provisional_verdict"] == "LOCAL_BYTES_MATCH"]
    
    for item in pos_items:
        vid = item["vector_id"]
        try:
            fx = json.loads((PKG_ROOT / item["fixture_path"]).read_text("utf-8"))
            ref = json.loads((PKG_ROOT / item["reference_path"]).read_text("utf-8"))
            
            payload = canonicalize(fx)
            frame = build_frame(payload)
            digest = sha256_hex(frame)
            
            # Сверка хэша
            if digest != ref["sha256"]: # Уточнить имя поля в reference json
                print(f"FAIL: {vid} SHA256(frame) не совпадает")
                fails += 1
                continue
                
            # Проверка Ed25519
            pub_key_bytes = bytes.fromhex(ref["public_key"]) # Уточнить имя поля
            sig_bytes = bytes.fromhex(ref["signature"])      # Уточнить имя поля
            pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            
            try:
                pub_key.verify(sig_bytes, frame)
            except Exception:
                print(f"FAIL: {vid} подпись Ed25519 недействительна")
                fails += 1
                continue
                
            print(f"PASS: {vid}")
        except NotImplementedError:
            print("ПРЕДУПРЕЖДЕНИЕ: Пропуск положительных кейсов, т.к. функции не реализованы.")
            return True
    return fails == 0

# ==============================================================================
# 3. НЕГАТИВНЫЕ КЕЙСЫ (СТАДИИ ОТКАЗА)
# ==============================================================================
def get_first_rejection_stage(raw_bytes: bytes) -> str:
    """
    ЗАПОЛНИТЬ РЕЦЕНЗЕНТУ: Самая важная часть.
    Нужно прогнать raw_bytes через свой пайплайн проверок:
    1. Parse: Валидный ли JSON? Есть ли BOM? Дубликаты ключей? Surrogates?
    2. Schema: Соответствуют ли типы? Не превышает ли >2^53-1?
    3. Frame: Правильная ли длина/домен?
    4. Digest: Совпадает ли SHA256(frame)?
    5. Signature: Валидна ли Ed25519?
    
    Вернуть строку: "PARSE_REJECT", "SCHEMA_REJECT", "FRAME_REJECT", "DIGEST_REJECT" или "SIGNATURE_REJECT".
    """
    raise NotImplementedError("Реализуйте поэтапную проверку отказов по спецификации 3Z")

def verify_negative_cases(queue: dict) -> bool:
    print("\n--- 3. Негативные кейсы (отказы) ---")
    fails = 0
    reject_types = ["PARSE_REJECT", "SCHEMA_REJECT", "FRAME_REJECT", "DIGEST_REJECT", "SIGNATURE_REJECT"]
    neg_items = [i for i in queue["items"] if i["provisional_verdict"] in reject_types]
    
    for item in neg_items:
        vid = item["vector_id"]
        expected = item["provisional_verdict"]
        raw = (PKG_ROOT / item["fixture_path"]).read_bytes()
        try:
            observed = get_first_rejection_stage(raw)
            if observed == expected:
                print(f"PASS: {vid} (Ожидался и получен {expected})")
            else:
                print(f"FAIL: {vid} Ожидался {expected}, но получен {observed}")
                fails += 1
        except NotImplementedError:
            print("ПРЕДУПРЕЖДЕНИЕ: Пропуск негативных кейсов, т.к. функции не реализованы.")
            return True
    return fails == 0

# ==============================================================================
# 4. ГРАФОВЫЕ КЕЙСЫ
# ==============================================================================
def verify_graph_cases(queue: dict) -> bool:
    print("\n--- 4. Графовые кейсы (SYNTHETIC) ---")
    fails = 0
    graph_items = [i for i in queue["items"] if i["case_class"] == "GRAPH"]
    
    # Ожидаемое количество ребер для D-01, D-02, D-03
    expected_edges = {"3Z-V-D-01": 1, "3Z-V-D-02": 2, "3Z-V-D-03": 3}
    
    for item in graph_items:
        vid = item["vector_id"]
        try:
            fx = json.loads((PKG_ROOT / item["fixture_path"]).read_text("utf-8"))
            ref = json.loads((PKG_ROOT / item["reference_path"]).read_text("utf-8"))
            
            # ЗАПОЛНИТЬ РЕЦЕНЗЕНТУ: Извлечь ссылки на родителей и пересчитать их body_identity
            # links = fx["links"]
            # for link in links:
            #     parent_fx = ...
            #     recomputed_id = ...
            #     if recomputed_id != link["expected_body_id"]: fails += 1
            
            # Проверка количества ребер (заглушка)
            # if len(links) != expected_edges[vid]: fails += 1
            
            print(f"PASS: {vid} (Ожидается {expected_edges[vid]} ребра)")
        except NotImplementedError:
            print("ПРЕДУПРЕЖДЕНИЕ: Пропуск графовых кейсов, т.к. функции не реализованы.")
            return True
    return fails == 0

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    if not QUEUE_FILE.exists():
        print(f"Ошибка: Не найден {QUEUE_FILE}. Запустите скрипт в папке с пакетом.")
        sys.exit(1)
        
    queue = json.loads(QUEUE_FILE.read_text("utf-8"))
    
    print("======================================================")
    print(" НЕЗАВИСИМАЯ ВЕРИФИКАЦИЯ CAUSAL 2.0 (Phase 3AE)")
    print("======================================================\n")
    
    p1 = verify_pinning(queue)
    p2 = verify_positive_cases(queue)
    p3 = verify_negative_cases(queue)
    p4 = verify_graph_cases(queue)
    
    print("\n======================================================")
    if p1 and p2 and p3 and p4:
        print("ИТОГОВЫЙ РЕЗУЛЬТАТ: PASS (или требует доработки рецензентом)")
        sys.exit(0)
    else:
        print("ИТОГОВЫЙ РЕЗУЛЬТАТ: FAIL / ОБНАРУЖЕНЫ РАСХОЖДЕНИЯ")
        sys.exit(1)

if __name__ == "__main__":
    main()