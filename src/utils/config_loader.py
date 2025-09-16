"""
Configuration loader utility
"""

import yaml
import os
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file with environment variable substitution
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    
    try:
        # Default configuration
        default_config = {
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            },
            "coral_protocol": {
                "max_message_history": 1000,
                "heartbeat_interval": 30,
                "message_timeout": 60
            },
            "agents": {
                "alert_receiver": {
                    "max_queue_size": 1000
                },
                "false_positive_checker": {
                    "confidence_threshold": 0.7,
                    "enable_ml_analysis": True
                }
            },
            "integrations": {
                "siem": {
                    "enabled": False
                },
                "soar": {
                    "enabled": False
                },
                "threat_intel": {
                    "enabled": False
                }
            },
            "api": {
                "webhook": {
                    "enabled": True,
                    "port": 8080,
                    "host": "0.0.0.0"
                }
            },
            "metrics": {
                "enabled": True,
                "prometheus_port": 9090
            }
        }
        
        # Load from file if it exists
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f)
                
            # Merge with defaults
            config = _deep_merge(default_config, file_config)
            logger.info(f"Loaded configuration from {config_path}")
        else:
            config = default_config
            logger.warning(f"Configuration file {config_path} not found, using defaults")
            
        # Substitute environment variables
        config = _substitute_env_vars(config)
        
        return config
        
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries
    
    Args:
        base: Base dictionary
        overlay: Dictionary to merge on top
        
    Returns:
        Merged dictionary
    """
    
    result = base.copy()
    
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
            
    return result


def _substitute_env_vars(config: Any) -> Any:
    """
    Recursively substitute environment variables in configuration
    
    Environment variables should be in format: ${ENV_VAR_NAME} or ${ENV_VAR_NAME:default_value}
    
    Args:
        config: Configuration value (can be dict, list, string, etc.)
        
    Returns:
        Configuration with environment variables substituted
    """
    
    if isinstance(config, dict):
        return {key: _substitute_env_vars(value) for key, value in config.items()}
    elif isinstance(config, list):
        return [_substitute_env_vars(item) for item in config]
    elif isinstance(config, str):
        return _substitute_env_var_string(config)
    else:
        return config


def _substitute_env_var_string(value: str) -> str:
    """
    Substitute environment variables in a string
    
    Args:
        value: String that may contain environment variable references
        
    Returns:
        String with environment variables substituted
    """
    
    import re
    
    # Pattern to match ${VAR_NAME} or ${VAR_NAME:default}
    pattern = r'\$\{([^}:]+)(?::([^}]*))?\}'
    
    def replace_env_var(match):
        var_name = match.group(1)
        default_value = match.group(2) if match.group(2) is not None else ''
        
        return os.environ.get(var_name, default_value)
    
    return re.sub(pattern, replace_env_var, value)


def validate_config(config: Dict[str, Any]) -> list:
    """
    Validate configuration and return list of validation errors
    
    Args:
        config: Configuration dictionary
        
    Returns:
        List of validation error messages
    """
    
    errors = []
    
    # Validate required sections
    required_sections = ['logging', 'coral_protocol', 'agents']
    for section in required_sections:
        if section not in config:
            errors.append(f"Missing required configuration section: {section}")
            
    # Validate agent configurations
    if 'agents' in config:
        agent_configs = config['agents']
        
        # Validate false positive checker
        if 'false_positive_checker' in agent_configs:
            fp_config = agent_configs['false_positive_checker']
            threshold = fp_config.get('confidence_threshold')
            if threshold is not None and not (0.0 <= threshold <= 1.0):
                errors.append("false_positive_checker.confidence_threshold must be between 0.0 and 1.0")
                
    # Validate API configuration
    if 'api' in config and 'webhook' in config['api']:
        webhook_config = config['api']['webhook']
        port = webhook_config.get('port')
        if port is not None and not (1 <= port <= 65535):
            errors.append("api.webhook.port must be between 1 and 65535")
            
    # Validate metrics configuration
    if 'metrics' in config:
        metrics_config = config['metrics']
        prom_port = metrics_config.get('prometheus_port')
        if prom_port is not None and not (1 <= prom_port <= 65535):
            errors.append("metrics.prometheus_port must be between 1 and 65535")
            
    return errors


# Configuration schemas for validation
CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "logging": {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR"]},
                "format": {"type": "string"}
            }
        },
        "coral_protocol": {
            "type": "object",
            "properties": {
                "max_message_history": {"type": "integer", "minimum": 100},
                "heartbeat_interval": {"type": "integer", "minimum": 10},
                "message_timeout": {"type": "integer", "minimum": 10}
            }
        },
        "agents": {
            "type": "object",
            "properties": {
                "alert_receiver": {
                    "type": "object",
                    "properties": {
                        "max_queue_size": {"type": "integer", "minimum": 10}
                    }
                },
                "false_positive_checker": {
                    "type": "object", 
                    "properties": {
                        "confidence_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        "enable_ml_analysis": {"type": "boolean"}
                    }
                }
            }
        }
    },
    "required": ["logging", "coral_protocol", "agents"]
}


def get_config_template() -> str:
    """
    Get a configuration file template
    
    Returns:
        YAML configuration template as string
    """
    
    template = """
# Alert Triage System Configuration

# Logging configuration
logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: logs/alert_triage.log

# Coral Protocol settings
coral_protocol:
  max_message_history: 1000
  heartbeat_interval: 30
  message_timeout: 60

# Agent configurations
agents:
  alert_receiver:
    max_queue_size: 1000
    supported_systems:
      - splunk
      - qradar
      - sentinel
      - edr
      - ids
      
  false_positive_checker:
    confidence_threshold: 0.7
    enable_ml_analysis: true
    ml_model_path: data/models/false_positive_model.pkl
    
  severity_analyzer:
    severity_rules_path: config/severity_rules.yaml
    
  context_gatherer:
    threat_intel_enabled: true
    user_context_enabled: true
    network_context_enabled: true
    
  response_coordinator:
    auto_escalation_threshold: 0.8
    default_analyst: tier1_analyst

# External integrations
integrations:
  siem:
    enabled: ${SIEM_ENABLED:false}
    type: ${SIEM_TYPE:splunk}
    endpoint: ${SIEM_ENDPOINT:}
    api_key: ${SIEM_API_KEY:}
    
  soar:
    enabled: ${SOAR_ENABLED:false}
    type: ${SOAR_TYPE:phantom}
    endpoint: ${SOAR_ENDPOINT:}
    api_key: ${SOAR_API_KEY:}
    
  threat_intel:
    enabled: ${THREAT_INTEL_ENABLED:false}
    providers:
      virustotal:
        api_key: ${VT_API_KEY:}
      misp:
        url: ${MISP_URL:}
        key: ${MISP_KEY:}

# API settings
api:
  webhook:
    enabled: true
    host: 0.0.0.0
    port: ${WEBHOOK_PORT:8080}
    secret: ${WEBHOOK_SECRET:}
    
  rest:
    enabled: true
    host: 0.0.0.0
    port: ${API_PORT:8081}

# Metrics and monitoring
metrics:
  enabled: true
  prometheus_port: ${PROMETHEUS_PORT:9090}
  
monitoring:
  health_check_interval: 60
  alert_on_failure: true
  
# Security settings
security:
  api_key_required: ${API_KEY_REQUIRED:true}
  rate_limiting: true
  max_requests_per_minute: 1000
"""
    
    return template.strip()