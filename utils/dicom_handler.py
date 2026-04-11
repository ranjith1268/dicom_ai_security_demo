import pydicom

def load_dicom(file):
    ds = pydicom.dcmread(file)
    return ds

def extract_metadata(ds):
    metadata = {
        "Patient Name": str(ds.get("PatientName", "Not Available")),
        "Patient ID": str(ds.get("PatientID", "Not Available")),
        "Study Date": str(ds.get("StudyDate", "Not Available")),
        "Modality": str(ds.get("Modality", "Not Available")),
    }
    return metadata

def modify_metadata(ds, new_name="Anonymous"):
    ds.PatientName = new_name
    return ds