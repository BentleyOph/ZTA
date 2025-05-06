import pandas as pd
import numpy as np
import json
import os
from datetime import datetime, timedelta
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
import sys

# --- Configuration ---
# Adjust the path to access_requests.json relative to this script's location
PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
ACCESS_REQUESTS_FILE = os.path.join(PARENT_DIR, 'access_requests.json')
MODEL_SAVE_PATH = os.path.join(os.path.dirname(__file__), 'isolation_forest_model.joblib')
PREPROCESSOR_SAVE_PATH = os.path.join(os.path.dirname(__file__), 'iforest_preprocessor.joblib')
FEATURE_NAMES_SAVE_PATH = os.path.join(os.path.dirname(__file__), 'iforest_feature_names.json')

# --- Data Loading ---
def load_data(filepath):
    """Loads access request data from JSON file."""
    print(f"Loading data from: {filepath}")
    try:
        df = pd.read_json(filepath, orient='records')
        print(f"Loaded {len(df)} records.")
        # Convert timestamp immediately
        df['access_request_time'] = pd.to_datetime(df['access_request_time'])
        # Ensure ID is treated as an object/string if needed later, though not used as feature here
        if 'ID' in df.columns:
             df['ID'] = df['ID'].astype(str)
        return df
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading data: {e}")
        sys.exit(1)

# --- Feature Engineering ---

def engineer_features(df):
    """Engineers features for anomaly detection."""
    print("Starting feature engineering...")
    df = df.copy() # Avoid modifying the original DataFrame

    # Handle potential missing values before processing
    df['location'] = df['location'].fillna('Unknown/Unknown')
    df['device_OS'] = df['device_OS'].fillna('Unknown')
    df['device_type'] = df['device_type'].fillna('Unknown')
    df['resource_requested'] = df['resource_requested'].fillna('Unknown')

    # 1. Temporal Features
    df['hour'] = df['access_request_time'].dt.hour
    df['day_of_week'] = df['access_request_time'].dt.dayofweek # Monday=0, Sunday=6

    # Cyclical encoding for hour and day
    df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
    df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)
    df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
    df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)

    # Time since last request (per user)
    df.sort_values(by=['user_id', 'access_request_time'], inplace=True)
    df['time_since_last_req_sec'] = df.groupby('user_id')['access_request_time'].diff().dt.total_seconds()
    # Fill NaN for the first request of each user (or if only one request exists)
    df['time_since_last_req_sec'] = df['time_since_last_req_sec'].fillna(0)

    # 2. Contextual Features (will be handled by OneHotEncoder)
    # Extract country code for location
    df['country'] = df['location'].apply(lambda x: x.split('/')[-1] if isinstance(x, str) and '/' in x else 'Unknown')

    # 3. Frequency Features (Per User) - More complex, calculating rolling counts
    print("Calculating frequency features (this might take a moment)...")
    df.sort_values(by='access_request_time', inplace=True) # Sort by time for rolling calculations

    # --- Rolling Requests per Hour (Lookback 1 hour) ---
    requests_per_hour = df.groupby('user_id').rolling('1h', on='access_request_time').count()['ID'] # Use 'ID' or any non-null column for counting
    # Correctly align the index after rolling
    requests_per_hour.index = requests_per_hour.index.droplevel(0) # Remove the user_id multi-index level temporarily for alignment
    df = df.join(requests_per_hour.rename('requests_last_1h'))
    df['requests_last_1h'] = df['requests_last_1h'].fillna(0)
    # Subtract 1 because rolling includes the current row
    df['requests_last_1h'] = (df['requests_last_1h'] - 1).clip(lower=0)


    # --- Rolling Requests per Day (Lookback 24 hours) ---
    requests_per_day = df.groupby('user_id').rolling('24h', on='access_request_time').count()['ID']
    requests_per_day.index = requests_per_day.index.droplevel(0)
    df = df.join(requests_per_day.rename('requests_last_24h'))
    df['requests_last_24h'] = df['requests_last_24h'].fillna(0)
     # Subtract 1 because rolling includes the current row
    df['requests_last_24h'] = (df['requests_last_24h'] - 1).clip(lower=0)

    print("Frequency features calculated.")

    # Select final features (excluding intermediate ones like 'hour', 'day_of_week')
    # Define numerical and categorical features AFTER creation
    numerical_features = ['hour_sin', 'hour_cos', 'day_sin', 'day_cos', 'time_since_last_req_sec', 'requests_last_1h', 'requests_last_24h']
    categorical_features = ['resource_requested', 'country', 'device_OS', 'device_type']

    # Keep only selected features and user_id/time if needed for debugging/analysis
    # For training, we only need the feature columns
    feature_columns = numerical_features + categorical_features
    df_final = df[feature_columns].copy()

    print("Feature engineering completed.")
    print("Selected features:", feature_columns)
    print("Sample of engineered data:\n", df_final.head())

    return df_final, numerical_features, categorical_features

# --- Model Training ---
def train_model(X, numerical_features, categorical_features):
    """Trains the Isolation Forest model with preprocessing."""
    print("Starting model training...")

    # Create preprocessing pipelines for numerical and categorical features
    numerical_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore') # Ignore unknown categories during prediction

    # Create a column transformer to apply different transformations
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numerical_transformer, numerical_features),
            ('cat', categorical_transformer, categorical_features)
        ],
        remainder='passthrough' # Keep other columns if any (shouldn't be if X only contains feature cols)
    )

    # Define the Isolation Forest model
    # Contamination 'auto' is roughly 10%, adjust if needed, e.g., 0.01 for 1%
    model = IsolationForest(n_estimators=150,      # Increased estimators slightly
                            max_samples='auto',
                            contamination='auto', # Let the model estimate, or set explicitly (e.g., 0.05 for 5%)
                            random_state=42,
                            n_jobs=-1)            # Use all available CPU cores

    # Create the full pipeline: preprocess -> model
    pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                               ('isolationforest', model)])

    # Fit the pipeline on the data (X should be the DataFrame with features)
    pipeline.fit(X)
    print("Model training completed.")

    # Extract feature names after one-hot encoding
    feature_names_out = pipeline.named_steps['preprocessor'].get_feature_names_out()
    print(f"Total features after preprocessing: {len(feature_names_out)}")


    # Save the entire pipeline (includes preprocessor and model)
    joblib.dump(pipeline, MODEL_SAVE_PATH)
    print(f"Trained pipeline saved to: {MODEL_SAVE_PATH}")

    # Save the feature names for consistency during prediction
    with open(FEATURE_NAMES_SAVE_PATH, 'w') as f:
        json.dump(feature_names_out.tolist(), f)
    print(f"Feature names saved to: {FEATURE_NAMES_SAVE_PATH}")

    # Optional: Save just the preprocessor if needed separately (though pipeline is better)
    # joblib.dump(preprocessor, PREPROCESSOR_SAVE_PATH)
    # print(f"Preprocessor saved to: {PREPROCESSOR_SAVE_PATH}")

    return pipeline, feature_names_out

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Load Data
    raw_df = load_data(ACCESS_REQUESTS_FILE)

    # 2. Engineer Features
    features_df, num_cols, cat_cols = engineer_features(raw_df)

    # Check for NaNs after feature engineering before training
    if features_df.isnull().sum().any():
        print("\nWarning: NaN values found after feature engineering:")
        print(features_df.isnull().sum())
        print("Attempting to fill NaNs with 0 for numerical and 'Unknown' for categorical before training.")
        # Impute NaNs - Simple strategy (you might need more sophisticated imputation)
        for col in num_cols:
             if features_df[col].isnull().any():
                  features_df[col].fillna(0, inplace=True)
        for col in cat_cols:
             if features_df[col].isnull().any():
                  features_df[col].fillna('Unknown', inplace=True)
        # Double check
        if features_df.isnull().sum().any():
             print("Error: NaNs still present after attempting imputation. Exiting.")
             sys.exit(1)
        else:
             print("NaNs handled.")


    # 3. Train Model (using the feature DataFrame)
    trained_pipeline, final_feature_names = train_model(features_df, num_cols, cat_cols)

    # Optional: Predict on training data to see anomaly scores
    # Note: Use the pipeline for prediction as it includes preprocessing
    print("\nPredicting on training data (lower scores are more normal):")
    anomaly_scores = trained_pipeline.decision_function(features_df)
    predictions = trained_pipeline.predict(features_df) # Returns 1 for inliers, -1 for outliers

    results_df = features_df.copy()
    results_df['anomaly_score'] = anomaly_scores
    results_df['is_anomaly'] = predictions
    results_df['is_anomaly'] = results_df['is_anomaly'].map({1: False, -1: True}) # Map to boolean

    print("Anomaly score distribution (sample):")
    print(results_df['anomaly_score'].describe())

    print("\nSample of predictions:")
    print(results_df.head())

    print("\nAnomalies detected in training data:")
    print(results_df[results_df['is_anomaly'] == True])

    print("\nTraining script finished successfully.")