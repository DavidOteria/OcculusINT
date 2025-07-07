import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_parallel(func, items, max_workers=20, show_progress=False):
    """
    Executes a function over a list of items in parallel (threaded),
    with optional progress display and error handling.

    :param func: Function to apply to each item
    :param items: List of items to process
    :param max_workers: Maximum number of concurrent threads
    :param show_progress: Whether to display a progress bar in the console
    :return: (list of results, list of (item, exception) for failures)
    """
    results = []
    errors = []
    total = len(items)
    completed = 0

    # Launch all tasks using a thread pool
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(func, item): item for item in items}

        # Initial progress bar display
        if show_progress:
            bar_len = 40
            sys.stdout.write(f"Progress: [{' ' * bar_len}] 0% (0/{total})")
            sys.stdout.flush()

        # Process results as they complete
        for future in as_completed(futures):
            item = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                errors.append((item, e))
                print(f"\n[✗] Error processing {item}: {e}")

            # Update progress bar
            if show_progress:
                completed += 1
                filled = int(bar_len * completed / total)
                bar = "=" * filled + " " * (bar_len - filled)
                pct = int(100 * completed / total)
                sys.stdout.write(f"\rProgress: [{bar}] {pct}% ({completed}/{total})")
                sys.stdout.flush()

        # Move to next line after final update
        if show_progress:
            sys.stdout.write("\n")

    return results, errors