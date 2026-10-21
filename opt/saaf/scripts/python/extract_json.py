import json


def extract_json_from_stdout(stdout: str) -> dict:
    """
    Extrae el ultimo objeto JSON valido de stdout.
        Usa rfind para encontrar el ultimo '{' y decodifica desde ahi.
    """
    stdout = stdout.strip()
    # Intento directo (caso mas comun)
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass
    
    # Buscar el ultimo '{' y desde alli intentar decodificar
    decoder = json.JSONDecoder()
    last_brace = stdout.rfind('{')
    if last_brace == -1:
        raise ValueError("No se encontro '{' en stdout")
    
    try:
        obj, end = decoder.raw_decode(stdout, last_brace)
        if end == len(stdout) or stdout[end:].strip() == '':
            # Si despues del JSON solo hay whitespace, es valido
            return obj
        else:
            # Puede haber basura despues -> buscar otro '{' mas atras
            i = last_brace - 1
            while i >= 0:
                if stdout[i] == '{':
                    try:
                        obj2, end2 = decoder.raw_decode(stdout, i)
                        if end2 > i and isinstance(obj2, dict):
                            return obj2
                    except json.JSONDecodeError:
                        pass
                i -= 1
            raise ValueError("No valid JSON object found")
    except json.JSONDecodeError:
        raise ValueError("No valid JSON object found")
