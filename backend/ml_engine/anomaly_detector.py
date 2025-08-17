"""
Machine Learning-based anomaly detection for ECU firmware analysis.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import joblib
import logging
from typing import Dict, List, Any, Tuple
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class FirmwareFeatureExtractor:
    """Extract features from firmware analysis results for ML models."""
    
    def __init__(self):
        self.feature_names = []
        self.scaler = StandardScaler()
        self.label_encoders = {}
    
    def extract_features(self, analysis_results: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from firmware analysis results."""
        features = []
        
        # File metadata features
        file_info = analysis_results.get('file_info', {})
        features.extend([
            file_info.get('size', 0),
            len(analysis_results.get('strings', [])),
            analysis_results.get('entropy', 0.0),
        ])
        
        # Pattern-based features
        patterns = analysis_results.get('patterns', {})
        features.extend([
            len(patterns.get('null_bytes', [])),
            len(patterns.get('repeated_bytes', [])),
            len(patterns.get('suspicious_sequences', [])),
        ])
        
        # ELF-specific features
        elf_analysis = analysis_results.get('elf_analysis', {})
        if elf_analysis and 'error' not in elf_analysis:
            features.extend([
                len(elf_analysis.get('sections', [])),
                len(elf_analysis.get('symbols', [])),
                len(elf_analysis.get('vulnerabilities', [])),
            ])
        else:
            features.extend([0, 0, 0])
        
        # PE-specific features
        pe_analysis = analysis_results.get('pe_analysis', {})
        if pe_analysis and 'error' not in pe_analysis:
            features.extend([
                len(pe_analysis.get('sections', [])),
                len(pe_analysis.get('imports', [])),
                len(pe_analysis.get('vulnerabilities', [])),
            ])
        else:
            features.extend([0, 0, 0])
        
        # Vulnerability count features
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        features.extend(severity_counts.values())
        
        return np.array(features).reshape(1, -1)
    
    def extract_text_features(self, analysis_results: Dict[str, Any]) -> np.ndarray:
        """Extract text-based features using TF-IDF."""
        # Combine all text data
        text_data = []
        
        # Add strings
        strings = analysis_results.get('strings', [])
        text_data.extend(strings)
        
        # Add vulnerability descriptions
        vulnerabilities = analysis_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            text_data.append(vuln.get('description', ''))
            text_data.append(vuln.get('title', ''))
        
        # Add section names for ELF/PE files
        elf_analysis = analysis_results.get('elf_analysis', {})
        if elf_analysis and 'error' not in elf_analysis:
            for section in elf_analysis.get('sections', []):
                text_data.append(section.get('name', ''))
        
        pe_analysis = analysis_results.get('pe_analysis', {})
        if pe_analysis and 'error' not in pe_analysis:
            for section in pe_analysis.get('sections', []):
                text_data.append(section.get('name', ''))
        
        # Combine all text
        combined_text = ' '.join(text_data)
        
        # Use TF-IDF vectorization
        vectorizer = TfidfVectorizer(
            max_features=100,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        try:
            features = vectorizer.fit_transform([combined_text]).toarray()
            return features
        except Exception as e:
            logger.error(f"Error in text feature extraction: {e}")
            return np.zeros((1, 100))


class AnomalyDetector:
    """Isolation Forest-based anomaly detection for firmware."""
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.feature_extractor = FirmwareFeatureExtractor()
        self.is_fitted = False
        
        if model_path and Path(model_path).exists():
            self.load_model(model_path)
    
    def train(self, training_data: List[Dict[str, Any]], contamination: float = 0.1):
        """Train the anomaly detection model."""
        try:
            # Extract features from training data
            features_list = []
            for analysis_result in training_data:
                features = self.feature_extractor.extract_features(analysis_result)
                features_list.append(features.flatten())
            
            if not features_list:
                logger.error("No valid features extracted from training data")
                return False
            
            # Convert to numpy array
            X = np.array(features_list)
            
            # Scale features
            X_scaled = self.feature_extractor.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            
            self.model.fit(X_scaled)
            self.is_fitted = True
            
            logger.info(f"Anomaly detection model trained with {len(X)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Error training anomaly detection model: {e}")
            return False
    
    def detect_anomalies(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in firmware analysis results."""
        if not self.is_fitted or self.model is None:
            return {
                'anomaly_score': None,
                'is_anomaly': None,
                'confidence': None,
                'error': 'Model not trained'
            }
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(analysis_results)
            
            # Scale features
            features_scaled = self.feature_extractor.scaler.transform(features)
            
            # Predict anomaly score
            anomaly_score = self.model.score_samples(features_scaled)[0]
            
            # Predict if it's an anomaly (1 for normal, -1 for anomaly)
            prediction = self.model.predict(features_scaled)[0]
            is_anomaly = prediction == -1
            
            # Calculate confidence based on score
            confidence = self._calculate_confidence(anomaly_score)
            
            return {
                'anomaly_score': float(anomaly_score),
                'is_anomaly': bool(is_anomaly),
                'confidence': confidence,
                'features_used': len(features.flatten())
            }
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return {
                'anomaly_score': None,
                'is_anomaly': None,
                'confidence': None,
                'error': str(e)
            }
    
    def _calculate_confidence(self, anomaly_score: float) -> float:
        """Calculate confidence score based on anomaly score."""
        # Normalize anomaly score to confidence (0-1)
        # Lower anomaly scores indicate more anomalous behavior
        # We want higher confidence for more anomalous cases
        
        # Use sigmoid function to map to 0-1 range
        confidence = 1 / (1 + np.exp(anomaly_score))
        return float(confidence)
    
    def save_model(self, model_path: str):
        """Save the trained model."""
        if not self.is_fitted:
            logger.error("Cannot save untrained model")
            return False
        
        try:
            model_data = {
                'model': self.model,
                'scaler': self.feature_extractor.scaler,
                'feature_names': self.feature_extractor.feature_names
            }
            joblib.dump(model_data, model_path)
            logger.info(f"Model saved to {model_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self, model_path: str):
        """Load a trained model."""
        try:
            model_data = joblib.load(model_path)
            self.model = model_data['model']
            self.feature_extractor.scaler = model_data['scaler']
            self.feature_extractor.feature_names = model_data.get('feature_names', [])
            self.is_fitted = True
            logger.info(f"Model loaded from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False


class VulnerabilityPredictor:
    """Machine learning model for predicting vulnerability likelihood."""
    
    def __init__(self, model_path: str = None):
        self.model = None
        self.feature_extractor = FirmwareFeatureExtractor()
        self.is_fitted = False
    
    def train(self, training_data: List[Dict[str, Any]], labels: List[str]):
        """Train the vulnerability prediction model."""
        try:
            # Extract features
            features_list = []
            for analysis_result in training_data:
                features = self.feature_extractor.extract_features(analysis_result)
                features_list.append(features.flatten())
            
            if not features_list:
                logger.error("No valid features extracted from training data")
                return False
            
            X = np.array(features_list)
            y = np.array(labels)
            
            # Scale features
            X_scaled = self.feature_extractor.scaler.fit_transform(X)
            
            # Train Random Forest classifier
            self.model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                class_weight='balanced'
            )
            
            self.model.fit(X_scaled, y)
            self.is_fitted = True
            
            logger.info(f"Vulnerability prediction model trained with {len(X)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Error training vulnerability prediction model: {e}")
            return False
    
    def predict_vulnerability(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Predict vulnerability likelihood."""
        if not self.is_fitted or self.model is None:
            return {
                'prediction': None,
                'confidence': None,
                'error': 'Model not trained'
            }
        
        try:
            # Extract features
            features = self.feature_extractor.extract_features(analysis_results)
            
            # Scale features
            features_scaled = self.feature_extractor.scaler.transform(features)
            
            # Make prediction
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            
            # Get confidence (probability of predicted class)
            confidence = max(probabilities)
            
            return {
                'prediction': str(prediction),
                'confidence': float(confidence),
                'probabilities': {cls: float(prob) for cls, prob in zip(self.model.classes_, probabilities)}
            }
            
        except Exception as e:
            logger.error(f"Error in vulnerability prediction: {e}")
            return {
                'prediction': None,
                'confidence': None,
                'error': str(e)
            }


class MLEngine:
    """Main machine learning engine orchestrator."""
    
    def __init__(self, models_dir: str = 'models/'):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        
        self.anomaly_detector = AnomalyDetector()
        self.vulnerability_predictor = VulnerabilityPredictor()
        
        # Load pre-trained models if available
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models from disk."""
        anomaly_model_path = self.models_dir / 'anomaly_detector.pkl'
        if anomaly_model_path.exists():
            self.anomaly_detector.load_model(str(anomaly_model_path))
        
        vuln_model_path = self.models_dir / 'vulnerability_predictor.pkl'
        if vuln_model_path.exists():
            self.vulnerability_predictor.load_model(str(vuln_model_path))
    
    def analyze_firmware(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive ML analysis on firmware."""
        results = {
            'anomaly_detection': {},
            'vulnerability_prediction': {},
            'ml_insights': {}
        }
        
        # Anomaly detection
        if self.anomaly_detector.is_fitted:
            results['anomaly_detection'] = self.anomaly_detector.detect_anomalies(analysis_results)
        
        # Vulnerability prediction
        if self.vulnerability_predictor.is_fitted:
            results['vulnerability_prediction'] = self.vulnerability_predictor.predict_vulnerability(analysis_results)
        
        # Generate ML insights
        results['ml_insights'] = self._generate_insights(analysis_results, results)
        
        return results
    
    def _generate_insights(self, analysis_results: Dict[str, Any], ml_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate insights from ML analysis results."""
        insights = {
            'risk_level': 'UNKNOWN',
            'recommendations': [],
            'confidence_indicators': []
        }
        
        # Determine risk level based on ML results
        anomaly_score = ml_results.get('anomaly_detection', {}).get('anomaly_score')
        vuln_prediction = ml_results.get('vulnerability_prediction', {}).get('prediction')
        
        if anomaly_score is not None and vuln_prediction:
            if anomaly_score < -0.5 and vuln_prediction == 'HIGH_RISK':
                insights['risk_level'] = 'CRITICAL'
            elif anomaly_score < -0.3 or vuln_prediction == 'HIGH_RISK':
                insights['risk_level'] = 'HIGH'
            elif anomaly_score < -0.1 or vuln_prediction == 'MEDIUM_RISK':
                insights['risk_level'] = 'MEDIUM'
            else:
                insights['risk_level'] = 'LOW'
        
        # Generate recommendations
        if insights['risk_level'] in ['CRITICAL', 'HIGH']:
            insights['recommendations'].append(
                "Immediate attention required. Consider manual review by security experts."
            )
            insights['recommendations'].append(
                "Check for known vulnerabilities in similar firmware versions."
            )
        
        if ml_results.get('anomaly_detection', {}).get('is_anomaly'):
            insights['recommendations'].append(
                "Firmware shows anomalous patterns. Verify authenticity and integrity."
            )
        
        # Confidence indicators
        anomaly_confidence = ml_results.get('anomaly_detection', {}).get('confidence')
        vuln_confidence = ml_results.get('vulnerability_prediction', {}).get('confidence')
        
        if anomaly_confidence:
            insights['confidence_indicators'].append(f"Anomaly detection confidence: {anomaly_confidence:.2f}")
        if vuln_confidence:
            insights['confidence_indicators'].append(f"Vulnerability prediction confidence: {vuln_confidence:.2f}")
        
        return insights
    
    def save_models(self):
        """Save all trained models."""
        anomaly_model_path = self.models_dir / 'anomaly_detector.pkl'
        self.anomaly_detector.save_model(str(anomaly_model_path))
        
        vuln_model_path = self.models_dir / 'vulnerability_predictor.pkl'
        self.vulnerability_predictor.save_model(str(vuln_model_path))
