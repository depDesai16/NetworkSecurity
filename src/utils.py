"""
Utility Module
Contains custom exceptions and helper functions
"""

import logging
import os
from datetime import datetime


# Custom Exception Classes
class IDSSimulationError(Exception):
    """Base exception for IDS simulation errors"""
    pass


class DataValidationError(IDSSimulationError):
    """Raised when data validation fails"""
    pass


class ModelError(IDSSimulationError):
    """Raised when model operations fail"""
    pass


class ConfigurationError(IDSSimulationError):
    """Raised when configuration is invalid"""
    pass


# Logging Setup
def setup_logging(log_dir: str = 'logs', log_level: int = logging.INFO) -> logging.Logger:
    """
    Set up logging configuration
    
    Args:
        log_dir: Directory to store log files
        log_level: Logging level (default: INFO)
    
    Returns:
        Configured logger instance
    """
    # Create logs directory
    os.makedirs(log_dir, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger('ids_simulation')
    logger.setLevel(log_level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # File handler - detailed logs
    log_file = os.path.join(log_dir, f'ids_simulation_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler - simple logs
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(simple_formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"Logging initialized. Log file: {log_file}")
    
    return logger


def validate_file_exists(filepath: str, file_description: str = "File") -> None:
    """
    Validate that a file exists
    
    Args:
        filepath: Path to the file
        file_description: Description of the file for error messages
    
    Raises:
        DataValidationError: If file doesn't exist
    """
    if not os.path.exists(filepath):
        raise DataValidationError(f"{file_description} not found: {filepath}")


def validate_directory_writable(dirpath: str) -> None:
    """
    Validate that a directory exists and is writable
    
    Args:
        dirpath: Path to the directory
    
    Raises:
        IDSSimulationError: If directory is not writable
    """
    os.makedirs(dirpath, exist_ok=True)
    
    if not os.access(dirpath, os.W_OK):
        raise IDSSimulationError(f"Directory is not writable: {dirpath}")


def validate_positive_integer(value: int, name: str) -> None:
    """
    Validate that a value is a positive integer
    
    Args:
        value: Value to validate
        name: Name of the parameter for error messages
    
    Raises:
        DataValidationError: If value is not a positive integer
    """
    if not isinstance(value, int) or value <= 0:
        raise DataValidationError(f"{name} must be a positive integer, got: {value}")


def validate_ratio(value: float, name: str) -> None:
    """
    Validate that a value is between 0 and 1
    
    Args:
        value: Value to validate
        name: Name of the parameter for error messages
    
    Raises:
        DataValidationError: If value is not between 0 and 1
    """
    if not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise DataValidationError(f"{name} must be between 0 and 1, got: {value}")
