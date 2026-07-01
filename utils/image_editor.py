import numpy as np
import cv2

from utils.audit_logger import run_hidden_process, log_breach_event


def _height_width(img):
    """Return (height, width) for grayscale or RGB images."""
    return img.shape[0], img.shape[1]


def _is_rgb_image(img):
    return img.ndim == 3 and img.shape[-1] in (3, 4)


def _extract_2d_image(image, ds=None):
    """Reduce pixel data to a single 2D frame for display, editing, and export."""
    if image.ndim == 2:
        return image, {"is_volume": False, "frame_index": 0, "frame_count": 1}

    if image.ndim != 3:
        raise ValueError(f"Unsupported image shape: {image.shape}")

    # Planar RGB: (3, H, W) or (4, H, W)
    if image.shape[0] in (3, 4) and image.shape[0] < image.shape[-1]:
        planar = np.transpose(image, (1, 2, 0))
        if planar.shape[-1] == 4:
            planar = planar[..., :3]
        return planar, {"is_volume": False, "frame_index": 0, "frame_count": 1}

    # Interleaved RGB(A): (H, W, 3|4)
    if image.shape[-1] in (3, 4):
        rgb = image[..., :3] if image.shape[-1] == 4 else image
        return rgb, {"is_volume": False, "frame_index": 0, "frame_count": 1}

    # Multi-frame volume: (frames, rows, cols)
    frame_count = int(getattr(ds, "NumberOfFrames", 0) or 0) if ds is not None else 0
    if frame_count <= 1:
        frame_count = image.shape[0]
    frame_index = frame_count // 2
    if frame_index >= image.shape[0]:
        frame_index = image.shape[0] // 2
    return image[frame_index], {
        "is_volume": frame_count > 1,
        "frame_index": frame_index,
        "frame_count": frame_count,
    }


def _to_grayscale(img):
    img, _ = _extract_2d_image(np.asarray(img))
    if img.ndim == 3 and _is_rgb_image(img):
        return cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    return img


def _draw_color(img):
    return (255,) if img.ndim == 2 else (255, 255, 255)


def dicom_to_image(ds):
    """Load pixels for display; preserve RGB exports (e.g. heatmap) as-is."""
    if getattr(ds, "EncapsulatedDocument", None):
        raise ValueError(
            "This DICOM stores an encapsulated document (e.g. PDF), not image pixels. "
            "Open it in a PDF-capable DICOM viewer or use the Payload Extractor tab."
        )

    try:
        image = ds.pixel_array
    except Exception as error:
        modality = str(getattr(ds, "Modality", "unknown"))
        raise ValueError(
            f"Cannot decode image pixels (modality={modality}). "
            f"The file may use an unsupported transfer syntax or have corrupt pixel data. "
            f"Detail: {error}"
        ) from error

    image, slice_info = _extract_2d_image(image, ds)
    ds._demo_slice_info = slice_info  # noqa: SLF001 — UI caption only

    if _is_rgb_image(image):
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
