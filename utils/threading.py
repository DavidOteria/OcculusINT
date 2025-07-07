from concurrent.futures import ThreadPoolExecutor, as_completed

def run_parallel(func, items, max_workers=20, show_progress=False):
    results = []
    errors = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(func, item): item for item in items}
        for future in as_completed(futures):
            item = futures[future]
            try:
                result = future.result()
                results.append(result)
                if show_progress:
                    print(f"[✓] {item}")
            except Exception as e:
                errors.append((item, e))
                print(f"[✗] Error processing {item}: {e}")
    
    return results, errors