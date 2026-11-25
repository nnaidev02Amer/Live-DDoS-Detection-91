"""Core engine of the DDoS detection and mitigation project.

Modules
-------
schema         column names and project-wide constants
sample_data    synthetic flow statistics (used because the real dataset is missing)
preprocessing  CSV reading, validation and cleaning
models         training, evaluation and saving of the ML models
detection      10 second window detection engine
mitigation     rule generation and mitigation simulation
sdn            SDN controller interface (only a simulated controller is provided)

Nothing in this package imports Streamlit, so it can be tested and reused on its own.
"""
