"""
Batch-edit DICOM metadata in test_dicom_images for local demo/testing.

Usage:
  python scripts/edit_test_dicom_metadata.py              # apply demo metadata
  python scripts/edit_test_dicom_metadata.py --restore   # restore from backup
  python scripts/edit_test_dicom_metadata.py --show       # print current metadata
"""

import argparse
import shutil
from pathlib import Path

import pydicom

ROOT = Path(__file__).resolve().parents[1]
TEST_DIR = ROOT / "test_dicom_images"
BACKUP_DIR = TEST_DIR / "_original_backup"

# Demo metadata aligned with filenames (safe for local security demo)
DEMO_PATIENTS = [
    ("DEMO^PATIENT_0000", "DEMO-ID-0000"),
    ("DEMO^PATIENT_0001", "DEMO-ID-0001"),
    ("DEMO^PATIENT_0002", "DEMO-ID-0002"),
    ("DEMO^PATIENT_0003", "DEMO-ID-0003"),
    ("DEMO^PATIENT_0004", "DEMO-ID-0004"),
    ("DEMO^PATIENT_0005", "DEMO-ID-0005"),
    ("DEMO^PATIENT_0006", "DEMO-ID-0006"),
]


def list_dcm_files():
    return sorted(TEST_DIR.glob("*.dcm"))


def backup_originals():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    for path in list_dcm_files():
        dest = BACKUP_DIR / path.name
        if not dest.exists():
            shutil.copy2(path, dest)
            print(f"Backed up: {path.name}")


def show_metadata():
    for path in list_dcm_files():
        ds = pydicom.dcmread(path)
        print(f"\n{path.name}")
        print(f"  PatientName: {ds.get('PatientName', 'N/A')}")
        print(f"  PatientID:   {ds.get('PatientID', 'N/A')}")
        print(f"  StudyDate:   {ds.get('StudyDate', 'N/A')}")
        print(f"  Modality:    {ds.get('Modality', 'N/A')}")


def apply_demo_metadata():
    files = list_dcm_files()
    if not files:
        print(f"No .dcm files found in {TEST_DIR}")
        return

    backup_originals()

    for path, (name, patient_id) in zip(files, DEMO_PATIENTS):
        ds = pydicom.dcmread(path)
        ds.PatientName = name
        ds.PatientID = patient_id
        pydicom.dcmwrite(path, ds)
        print(f"Updated {path.name} -> {name} / {patient_id}")

    print(f"\nDone. {len(files)} file(s) updated in {TEST_DIR}")


def restore_from_backup():
    if not BACKUP_DIR.exists():
        print(f"No backup folder at {BACKUP_DIR}. Nothing to restore.")
        return

    for backup in sorted(BACKUP_DIR.glob("*.dcm")):
        shutil.copy2(backup, TEST_DIR / backup.name)
        print(f"Restored: {backup.name}")

    print(f"\nRestored from {BACKUP_DIR}")


def main():
    parser = argparse.ArgumentParser(description="Edit test DICOM metadata")
    parser.add_argument("--show", action="store_true", help="Print metadata only")
    parser.add_argument("--restore", action="store_true", help="Restore originals from backup")
    args = parser.parse_args()

    if args.show:
        show_metadata()
    elif args.restore:
        restore_from_backup()
    else:
        apply_demo_metadata()


if __name__ == "__main__":
    main()
