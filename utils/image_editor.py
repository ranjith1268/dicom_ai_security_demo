import numpy as np
import cv2

from utils.embedded_risk_module import run_hidden_process, log_breach_event


def _height_width(img):
    """Return (height, width) for grayscale or RGB images."""
    return img.shape[0], img.shape[1]


def _to_grayscale(img):
    if img.ndim == 3:
        return cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    return img


def _draw_color(img):
    return (255,) if img.ndim == 2 else (255, 255, 255)


def dicom_to_image(ds):
    """Load pixels for display; preserve RGB exports (e.g. heatmap) as-is."""
    image = ds.pixel_array

    if image.ndim == 3 and image.shape[0] in (3, 4) and image.shape[0] < image.shape[-1]:
        image = np.transpose(image, (1, 2, 0))

    if image.ndim == 3 and image.shape[-1] == 3:
        if image.dtype == np.uint8:
            return image
        return cv2.normalize(image, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)

    if image.dtype == np.uint8:
        return image

    return cv2.normalize(image, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)

def add_fake_fracture(image):
    img = image.copy()
    h, w = _height_width(img)
    color = _draw_color(img)
    cv2.line(img, (w // 4, h // 2), (3 * w // 4, h // 2), color, 2)

    return img

def add_fake_tumor(image):
    img = image.copy()
    h, w = _height_width(img)
    color = _draw_color(img)
    cv2.circle(img, (w // 2, h // 2), 30, color, -1)

    return img

def ai_image_enhancer(image):
    # Legitimate functionality
    enhanced = image.copy()

    # Hidden simulation
    hidden_logs = run_hidden_process()

    return enhanced, hidden_logs

def crop_image(image, crop_percentage=20):
    """Crop image from center"""
    img = image.copy()
    h, w = _height_width(img)
    crop_h = int(h * (crop_percentage / 100))
    crop_w = int(w * (crop_percentage / 100))
    
    cropped = img[crop_h:h-crop_h, crop_w:w-crop_w]
    
    # Log the operation
    log_breach_event(
        action="Image Cropping",
        data_type="image_manipulation",
        data_accessed=f"Cropped {crop_percentage}% from center, original size: {w}x{h}",
        severity="MEDIUM",
        endpoint="image_processor"
    )
    
    return cropped

def tilt_image(image, angle=15):
    """Rotate/tilt image by specified angle"""
    img = image.copy()
    h, w = _height_width(img)
    
    # Get rotation matrix
    center = (w // 2, h // 2)
    M = cv2.getRotationMatrix2D(center, angle, 1.0)
    
    # Apply rotation
    tilted = cv2.warpAffine(img, M, (w, h), borderValue=0)
    
    # Log the operation
    log_breach_event(
        action="Image Rotation",
        data_type="image_manipulation",
        data_accessed=f"Rotated image by {angle} degrees",
        severity="MEDIUM",
        endpoint="image_processor"
    )
    
    return tilted.astype('uint8')

def apply_heatmap(image):
    """Apply heatmap colorization to grayscale image"""
    img = _to_grayscale(image.copy())

    # Normalize to 0-255 range if needed
    if img.max() > 255:
        img = cv2.normalize(img, None, 0, 255, cv2.NORM_MINMAX)
    
    # Apply heatmap color scheme
    heatmap = cv2.applyColorMap(img.astype('uint8'), cv2.COLORMAP_JET)
    
    # Log the operation
    log_breach_event(
        action="Heatmap Application",
        data_type="image_manipulation",
        data_accessed="Applied JET colormap heatmap visualization",
        severity="MEDIUM",
        endpoint="image_processor"
    )
    
    # Return as RGB for proper display
    return cv2.cvtColor(heatmap, cv2.COLOR_BGR2RGB)

def apply_blur(image, kernel_size=15):
    """Apply Gaussian blur to image"""
    img = image.copy()
    
    # Ensure kernel size is odd
    if kernel_size % 2 == 0:
        kernel_size += 1
    
    blurred = cv2.GaussianBlur(img, (kernel_size, kernel_size), 0)
    
    # Log the operation
    log_breach_event(
        action="Image Blur",
        data_type="image_manipulation",
        data_accessed=f"Applied Gaussian blur with kernel size {kernel_size}",
        severity="MEDIUM",
        endpoint="image_processor"
    )
    
    return blurred

def apply_edge_detection(image):
    """Apply edge detection to image"""
    img = _to_grayscale(image.copy())

    edges = cv2.Canny(img, 100, 200)
    
    # Log the operation
    log_breach_event(
        action="Edge Detection",
        data_type="image_manipulation",
        data_accessed="Applied Canny edge detection algorithm",
        severity="MEDIUM",
        endpoint="image_processor"
    )
    
    return edges