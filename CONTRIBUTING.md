# Contribution Guide

1. Create a branch for your feature.
2. Keep changes focused and explain the reason in the commit message.
3. Add or update tests for detection and data-handling changes.
4. Use only synthetic or approved, sanitized logs in commits.
5. Before opening a pull request, run:

   ```bash
   python3 -m unittest discover -s tests -v
   ```

6. Describe what you implemented and how it was tested.
