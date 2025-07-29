//! Contains the data structures and implementation for predefined Stix Cyber-observable object extensions.
//!
//! These provide additional functionality and customization options for various SCOs

use crate::{
    base::Stix,
    cyber_observable_objects::vocab::{
        NetworkSocketAddressFamilyEnum, NetworkSocketTypeEnum, WindowsIntegrityEnum,
        WindowsServiceStartTypeEnum, WindowsServiceStatusEnum, WindowsServiceTypeEnum,
    },
    error::{add_error, return_multiple_errors, StixError as Error},
    types::{stix_case, DictionaryValue, Hashes, Identifier, StixDictionary, Timestamp},
};
use convert_case::{Case, Casing};
use log::warn;
use ordered_float::OrderedFloat as ordered_float;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_this_or_that::as_opt_i64;
use serde_with::skip_serializing_none;
use strum::{AsRefStr, EnumIter, IntoEnumIterator};

/// Known predefined extensions specific to particular SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SpecialExtensions {
    FileExtensions(FileExtensions),
    NetworkTrafficExtensions(NetworkTrafficExtensions),
    ProcessExtensions(ProcessExtensions),
    UserAccountExtensions(UserAccountExtensions),
}
use serde_this_or_that::as_opt_u64;

impl SpecialExtensions {
    /// Convert a known predefined extension to a raw extension dictionary
    pub fn extension_to_dict(&self) -> Result<StixDictionary<DictionaryValue>, Error> {
        serde_json::from_value(
            serde_json::to_value(self).map_err(|e| Error::SerializationError(e.to_string()))?,
        )
        .map_err(|e| Error::DeserializationError(e.to_string()))
    }
}

/// Validate a known predefined extension expressed as a raw extension dictionary
pub fn check_extension(key: &str, value: &StixDictionary<DictionaryValue>) -> Result<(), Error> {
    match stix_case(key).as_ref() {
        "archive-ext" => dict_to_extension::<ArchiveExtension>(value)?.stix_check(),
        "ntfs-ext" => dict_to_extension::<NtfsExtension>(value)?.stix_check(),
        "pdf-ext" => dict_to_extension::<PdfExtension>(value)?.stix_check(),
        "raster-ext" => dict_to_extension::<RasterExtension>(value)?.stix_check(),
        "windows-pebinary-ext" => {
            dict_to_extension::<WindowsPebinaryExtension>(value)?.stix_check()
        }
        "icmp-ext" => dict_to_extension::<IcmpExtension>(value)?.stix_check(),
        "http-request-ext" => dict_to_extension::<HttpRequestExtension>(value)?.stix_check(),
        "socket-ext" => dict_to_extension::<SocketExtenion>(value)?.stix_check(),
        "tcp-ext" => dict_to_extension::<TcpExtension>(value)?.stix_check(),
        "windows-process-ext" => dict_to_extension::<WindowsProcessExtension>(value)?.stix_check(),
        "windows-service-ext" => dict_to_extension::<WindowsServiceExtension>(value)?.stix_check(),
        "unix-account-ext" => dict_to_extension::<UnixAccountExtension>(value)?.stix_check(),
        _ => Err(Error::UnknownExtension),
    }
}

/// Convert a raw extension dictionary to a known predefined extension
fn dict_to_extension<T: DeserializeOwned>(
    dictionary: &StixDictionary<DictionaryValue>,
) -> Result<T, Error> {
    let extension: Result<T, Error> = serde_json::from_value(
        serde_json::to_value(dictionary).map_err(|e| Error::SerializationError(e.to_string()))?,
    )
    .map_err(|e| Error::DeserializationError(e.to_string()));
    extension
}

/// Possible extensions for File SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum FileExtensions {
    ArchiveExt(ArchiveExtension),
    NtfsExt(NtfsExtension),
    PdfExt(PdfExtension),
    RasterExt(RasterExtension),
    WindowsPebinaryExt(Box<WindowsPebinaryExtension>),
}

impl Stix for FileExtensions {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

/// Archive File Extension
///
/// The Archive File extension specifies a default extension for capturing properties
/// specific to archive files. The key for this extension when used in the extensions
/// dictionary **MUST** be archive-ext.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_xi3g7dwaigs6>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveExtension {
    /// This property specifies the files that are contained in the archive. It MUST contain references to one or more File objects.
    pub contains_refs: Vec<Identifier>,
    /// Specifies a comment included as part of the archive file.
    pub comment: Option<String>,
}

impl Stix for ArchiveExtension {
    fn stix_check(&self) -> Result<(), Error> {
        if self.contains_refs.iter().any(|x| x.get_type() != "file") {
            return Err(Error::ValidationError(
                "references must be of type file".to_string(),
            ));
        }
        Ok(())
    }
}
///  NFTS Extension
///
/// The NTFS file extension specifies a default extension for capturing properties
/// specific to the storage of the file on the NTFS file system. The key for this
/// extension when used in the extensions dictionary **MUST** be ntfs-ext.
///
/// An object using the NTFS File Extension **MUST** contain at least one property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_o6cweepfrsci>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtfsExtension {
    /// Specifies the security ID (SID) value assigned to the file.
    pub sid: Option<String>,
    /// Specifies a list of NTFS alternate data streams that exist for the file.
    pub alternate_data_streams: Option<Vec<AlternateDataStreamType>>,
}

impl Stix for NtfsExtension {
    fn stix_check(&self) -> Result<(), Error> {
        if self.sid.is_none() && self.alternate_data_streams.is_none() {
            return Err(Error::ValidationError(
                "at least one property must be set".to_string(),
            ));
        }
        Ok(())
    }
}

///  Alternate Data Stream Type
///
/// The Alternate Data Stream type represents an
/// NTFS alternate data stream.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlternateDataStreamType {
    /// Specifies the name of the alternate data stream.
    pub name: String,
    /// Specifies a dictionary of hashes for the data contained in the alternate data stream.
    pub hashes: Option<Hashes>,
    /// Specifies the size of the alternate data stream, in bytes. The value of this property MUST NOT be negative.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size: Option<u64>,
}

impl Stix for AlternateDataStreamType {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(hashes) = &self.hashes {
            hashes.stix_check()?;
        }
        if let Some(size) = &self.size {
            size.stix_check()
        } else {
            Ok(())
        }
    }
}

///  PDF File Extension
///
/// The PDF file extension specifies a default extension for capturing properties specific to PDF files.
/// The key for this extension when used in the extensions dictionary **MUST** be pdf-ext.
///
/// An object using the PDF File Extension **MUST** contain at least one property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8xmpb2ghp9km>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfExtension {
    /// Specifies the decimal version number of the string from the PDF header that specifies the version of the PDF specification to which the PDF file conforms. E.g., 1.4.
    pub version: Option<String>,
    /// Specifies whether the PDF file has been optimized.
    pub is_optimized: Option<bool>,
    /// Specifies details of the PDF document information dictionary (DID), which includes properties like the document creation data and producer, as a dictionary.
    pub document_info_dict: Option<StixDictionary<String>>,
    /// Specifies the first file identifier found for the PDF file.
    pub pdfid0: Option<String>,
    /// Specifies the second file identifier found for the PDF file.
    pub pdfid1: Option<String>,
}

impl Stix for PdfExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if self.version.is_none()
            && self.is_optimized.is_none()
            && self.document_info_dict.is_none()
            && self.pdfid0.is_none()
            && self.pdfid1.is_none()
        {
            errors.push(Error::ValidationError(
                "At least one property must be set".to_string(),
            ));
        }
        if let Some(document_info_dict) = &self.document_info_dict {
            add_error(&mut errors, document_info_dict.stix_check());
        }

        return_multiple_errors(errors)
    }
}

///  Raster Image File Extension
///  
/// The Raster Image file extension specifies a default extension for
/// capturing properties specific to raster image files. The key for this
/// extension when used in the extensions dictionary **MUST** be raster-image-ext.
///
/// An object using the Raster Image File Extension **MUST** contain at least one property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_u5z7i2ox8w4x>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RasterExtension {
    /// Specifies the height of the image in the image file, in pixels.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub image_height: Option<i64>,
    /// Specifies the width of the image in the image file, in pixels.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub image_width: Option<i64>,
    /// Specifies the sum of bits used for each color channel in the image file, and thus the total number of pixels used for expressing the color depth of the image.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub bits_per_pixel: Option<i64>,
    /// Specifies the set of EXIF tags found in the image file, as a dictionary. Each key/value pair in the dictionary represents the name/value of a single EXIF tag.
    pub exif_tags: Option<StixDictionary<ExifTag>>,
}

impl Stix for RasterExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if self.image_height.is_none()
            && self.image_width.is_none()
            && self.bits_per_pixel.is_none()
            && self.exif_tags.is_none()
        {
            errors.push(Error::ValidationError(
                "At least one property must be set".to_string(),
            ));
        }
        if let Some(image_height) = &self.image_height {
            add_error(&mut errors, image_height.stix_check());
        }
        if let Some(image_width) = &self.image_width {
            add_error(&mut errors, image_width.stix_check());
        }
        if let Some(bits_per_pixel) = &self.bits_per_pixel {
            add_error(&mut errors, bits_per_pixel.stix_check());
        }
        if let Some(exif_tags) = &self.exif_tags {
            add_error(&mut errors, exif_tags.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// An EXIF tag, which can be either a string or an integer representing EXIF metadata fields
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExifTag {
    String(String),
    Integer(i64),
}
impl Stix for ExifTag {
    fn stix_check(&self) -> Result<(), Error> {
        Ok(())
    }
}

///  Windows PE Binary File Extension
///
/// The Windows™ PE Binary File extension specifies a default extension for capturing properties
/// specific to Windows portable executable (PE) files. The key for this extension when used in the
/// extensions dictionary **MUST** be windows-pebinary-ext.
///
/// An object using the Windows™ PE Binary File Extension **MUST** contain at least one property
/// other than the required pe_type property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gg5zibddf9bs>
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPebinaryExtension {
    /// Specifies the type of the PE binary. This is an open vocabulary and values SHOULD come from the windows-pebinary-type-ov open vocabulary.
    pub pe_type: WindowsPebinaryTypeOv,
    /// Specifies the special import hash, or ‘imphash’, calculated for the PE Binary based on its imported libraries and functions.
    pub imphash: Option<String>,
    /// Specifies the type of target machine.
    pub machine_hex: Option<String>,
    /// Specifies the number of sections in the PE binary, as a non-negative integer.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub number_of_sections: Option<u64>,
    /// Specifies the time when the PE binary was created. The timestamp value MUST be precise to the second.
    pub time_date_stamp: Option<Timestamp>,
    /// Specifies the file offset of the COFF symbol table.
    pub pointer_to_symbol_table_hex: Option<String>,
    /// Specifies the number of entries in the symbol table of the PE binary, as a non-negative integer.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub number_of_symbols: Option<u64>,
    /// Specifies the size of the optional header of the PE binary. The value of this property MUST NOT be negative.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_optional_header: Option<u64>,
    /// Specifies the flags that indicate the file’s characteristics.
    pub characteristics_hex: Option<String>,
    /// Specifies any hashes that were computed for the file header.
    pub file_header_hashes: Option<Hashes>,
    /// Specifies the PE optional header of the PE binary
    pub optional_header: Option<WindowsPEOptionalHeaderType>,
    /// Specifies metadata about the sections in the PE file.
    pub sections: Option<Vec<WindowsPESectionType>>,
}

impl Stix for WindowsPebinaryExtension {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(file_header_hashes) = &self.file_header_hashes {
            file_header_hashes.stix_check()?;
        }
        let mut errors = Vec::new();
        if let Some(characteristics_hex) = &self.characteristics_hex {
            if hex::decode(characteristics_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "characteristics_hex -- ".to_string() + characteristics_hex,
                ))
            }
        }
        if let Some(machine_hex) = &self.machine_hex {
            if hex::decode(machine_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "machine_hex -- ".to_string() + machine_hex,
                ))
            }
        }
        if let Some(number_of_sections) = &self.number_of_sections {
            add_error(&mut errors, number_of_sections.stix_check());
        }
        if let Some(number_of_symbols) = &self.number_of_symbols {
            add_error(&mut errors, number_of_symbols.stix_check());
        }
        if let Some(pointer_to_symbol_table_hex) = &self.pointer_to_symbol_table_hex {
            if hex::decode(pointer_to_symbol_table_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "pointer_to_symbol_table_hex -- ".to_string() + pointer_to_symbol_table_hex,
                ))
            }
        }
        if let Some(size_of_optional_header) = &self.size_of_optional_header {
            add_error(&mut errors, size_of_optional_header.stix_check());
        }

        if self.imphash.is_none()
            && self.machine_hex.is_none()
            && self.number_of_sections.is_none()
            && self.time_date_stamp.is_none()
            && self.pointer_to_symbol_table_hex.is_none()
            && self.number_of_symbols.is_none()
            && self.size_of_optional_header.is_none()
            && self.characteristics_hex.is_none()
            && self.file_header_hashes.is_none()
            && self.optional_header.is_none() & self.sections.is_none()
        {
            errors.push(Error::ValidationError(
                "At least one property must be set".to_string(),
            ));
        }

        return_multiple_errors(errors)
    }
}

/// Possible types of a Windows PE binary, specifying a file extension for capturing properties specific to Windows portable executable (PE) files
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize, AsRefStr, EnumIter)]
pub enum WindowsPebinaryTypeOv {
    Dll,
    #[default]
    Exe,
    Sys,
    Other(String),
}
///  Windows™ PE Optional Header Type
///
/// The Windows PE Optional Header
/// type represents the properties of the PE optional header.
/// An object using the Windows PE Optional Header Type **MUST** contain at least one property from this type.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_29l09w731pzc>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPEOptionalHeaderType {
    /// Specifies the hex value that indicates the type of the PE binary.
    pub magic_hex: Option<String>,
    /// Specifies the linker major version number.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub major_linker_version: Option<i64>,
    /// Specifies the linker minor version number.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub minor_linker_version: Option<i64>,
    /// Specifies the size of the code (text) section. If there are multiple such sections, this refers to the sum of the sizes of each section.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_code: Option<u64>,
    /// Specifies the size of the initialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_initialized_data: Option<u64>,
    /// Specifies the size of the uninitialized data section. If there are multiple such sections, this refers to the sum of the sizes of each section.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_uninitialized_data: Option<u64>,
    /// Specifies the address of the entry point relative to the image base when the executable is loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub address_of_entry_point: Option<i64>,
    /// Specifies the address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub base_of_code: Option<i64>,
    /// Specifies the address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub base_of_data: Option<i64>,
    /// Specifies the preferred address of the first byte of the image when loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub image_base: Option<i64>,
    /// Specifies the alignment (in bytes) of PE sections when they are loaded into memory.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub section_alignment: Option<i64>,
    /// Specifies the factor (in bytes) that is used to align the raw data of sections in the image file.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub file_alignment: Option<i64>,
    /// Specifies the major version number of the required operating system.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub major_os_version: Option<i64>,
    /// Specifies the minor version number of the required operating system.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub minor_os_version: Option<i64>,
    /// Specifies the major version number of the image.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub major_image_version: Option<i64>,
    /// Specifies the minor version number of the image.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub minor_image_version: Option<i64>,
    /// Specifies the major version number of the subsystem.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub major_subsystem_version: Option<i64>,
    /// Specifies the minor version number of the subsystem.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub minor_subsystem_version: Option<i64>,
    /// Specifies the reserved win32 version value.
    pub win32_version_value_hex: Option<String>,
    /// Specifies the size of the image in bytes, including all headers, as the image is loaded in memory.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_image: Option<u64>,
    /// Specifies the size of the image in bytes, including all headers, as the image is loaded in memory.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_headers: Option<u64>,
    /// Specifies the checksum of the PE binary.
    pub checksum_hex: Option<String>,
    /// Specifies the subsystem (e.g., GUI, device driver, etc.) that is required to run this image.
    pub subsystem_hex: Option<String>,
    /// Specifies the flags that characterize the PE binary.
    pub dll_characteristics_hex: Option<String>,
    /// Specifies the size of the stack to reserve, in bytes
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_stack_reserve: Option<u64>,
    /// Specifies the size of the stack to commit, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_stack_commit: Option<u64>,
    /// Specifies the size of the local heap space to reserve, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_heap_reserve: Option<u64>,
    /// Specifies the size of the local heap space to commit, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size_of_heap_commit: Option<u64>,
    /// Specifies the reserved loader flags.
    pub loader_flags_hex: Option<String>,
    /// Specifies the number of data-directory entries in the remainder of the optional header.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub number_of_rva_and_sizes: Option<i64>,
    /// Specifies any hashes that were computed for the optional header.
    pub hashes: Option<Hashes>,
}

impl Stix for WindowsPEOptionalHeaderType {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(hashes) = &self.hashes {
            hashes.stix_check()?;
        }
        let mut errors = Vec::new();

        if let Some(size_of_code) = &self.size_of_code {
            add_error(&mut errors, size_of_code.stix_check());
        }
        if let Some(size_of_initialized_data) = &self.size_of_initialized_data {
            add_error(&mut errors, size_of_initialized_data.stix_check());
        }
        if let Some(size_of_uninitialized_data) = &self.size_of_uninitialized_data {
            add_error(&mut errors, size_of_uninitialized_data.stix_check());
        }
        if let Some(size_of_image) = &self.size_of_image {
            add_error(&mut errors, size_of_image.stix_check());
        }
        if let Some(size_of_headers) = &self.size_of_headers {
            add_error(&mut errors, size_of_headers.stix_check());
        }
        if let Some(size_of_stack_reserve) = &self.size_of_stack_reserve {
            add_error(&mut errors, size_of_stack_reserve.stix_check());
        }
        if let Some(size_of_stack_commit) = &self.size_of_stack_commit {
            add_error(&mut errors, size_of_stack_commit.stix_check());
        }
        if let Some(size_of_heap_reserve) = &self.size_of_heap_reserve {
            add_error(&mut errors, size_of_heap_reserve.stix_check());
        }
        if let Some(size_of_heap_commit) = &self.size_of_heap_commit {
            add_error(&mut errors, size_of_heap_commit.stix_check());
        }

        if let Some(magic_hex) = &self.magic_hex {
            if hex::decode(magic_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "magic_hex -- ".to_string() + magic_hex,
                ))
            }
        }
        if let Some(major_linker_version) = &self.major_linker_version {
            add_error(&mut errors, major_linker_version.stix_check());
        }
        if let Some(minor_linker_version) = &self.minor_linker_version {
            add_error(&mut errors, minor_linker_version.stix_check());
        }
        if let Some(address_of_entry_point) = &self.address_of_entry_point {
            add_error(&mut errors, address_of_entry_point.stix_check());
        }
        if let Some(base_of_code) = &self.base_of_code {
            add_error(&mut errors, base_of_code.stix_check());
        }
        if let Some(base_of_data) = &self.base_of_data {
            add_error(&mut errors, base_of_data.stix_check());
        }
        if let Some(image_base) = &self.image_base {
            add_error(&mut errors, image_base.stix_check());
        }
        if let Some(section_alignment) = &self.section_alignment {
            add_error(&mut errors, section_alignment.stix_check());
        }
        if let Some(file_alignment) = &self.file_alignment {
            add_error(&mut errors, file_alignment.stix_check());
        }
        if let Some(major_os_version) = &self.major_os_version {
            add_error(&mut errors, major_os_version.stix_check());
        }
        if let Some(minor_os_version) = &self.minor_os_version {
            add_error(&mut errors, minor_os_version.stix_check());
        }
        if let Some(major_image_version) = &self.major_image_version {
            add_error(&mut errors, major_image_version.stix_check());
        }
        if let Some(minor_image_version) = &self.minor_image_version {
            add_error(&mut errors, minor_image_version.stix_check());
        }
        if let Some(major_subsystem_version) = &self.major_subsystem_version {
            add_error(&mut errors, major_subsystem_version.stix_check());
        }
        if let Some(minor_subsystem_version) = &self.minor_subsystem_version {
            add_error(&mut errors, minor_subsystem_version.stix_check());
        }
        if let Some(win32_version_value_hex) = &self.win32_version_value_hex {
            if hex::decode(win32_version_value_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "win32_version_value_hex -- ".to_string() + win32_version_value_hex,
                ))
            }
        }
        if let Some(checksum_hex) = &self.checksum_hex {
            if hex::decode(checksum_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "checksum_hex -- ".to_string() + checksum_hex,
                ))
            }
        }
        if let Some(subsystem_hex) = &self.subsystem_hex {
            if hex::decode(subsystem_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "subsystem_hex -- ".to_string() + subsystem_hex,
                ))
            }
        }
        if let Some(dll_characteristics_hex) = &self.dll_characteristics_hex {
            if hex::decode(dll_characteristics_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "dll_characteristics_hex -- ".to_string() + dll_characteristics_hex,
                ))
            }
        }
        if let Some(loader_flags_hex) = &self.loader_flags_hex {
            if hex::decode(loader_flags_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "loader_flags_hex -- ".to_string() + loader_flags_hex,
                ))
            }
        }
        if let Some(number_of_rva_and_sizes) = &self.number_of_rva_and_sizes {
            add_error(&mut errors, number_of_rva_and_sizes.stix_check());
        }
        if self.magic_hex.is_none()
            && self.major_linker_version.is_none()
            && self.minor_linker_version.is_none()
            && self.size_of_code.is_none()
            && self.size_of_initialized_data.is_none()
            && self.size_of_uninitialized_data.is_none()
            && self.address_of_entry_point.is_none()
            && self.base_of_code.is_none()
            && self.base_of_data.is_none()
            && self.image_base.is_none()
            && self.section_alignment.is_none()
            && self.file_alignment.is_none()
            && self.major_os_version.is_none()
            && self.minor_os_version.is_none()
            && self.major_image_version.is_none()
            && self.minor_image_version.is_none()
            && self.major_subsystem_version.is_none()
            && self.minor_subsystem_version.is_none()
            && self.win32_version_value_hex.is_none()
            && self.size_of_image.is_none()
            && self.size_of_headers.is_none()
            && self.checksum_hex.is_none()
            && self.subsystem_hex.is_none()
            && self.dll_characteristics_hex.is_none()
            && self.size_of_stack_reserve.is_none()
            && self.size_of_stack_commit.is_none()
            && self.size_of_heap_commit.is_none()
            && self.size_of_heap_reserve.is_none()
            && self.loader_flags_hex.is_none()
            && self.number_of_rva_and_sizes.is_none()
            && self.hashes.is_none()
        {
            errors.push(Error::ValidationError(
                "At least one property must be set".to_string(),
            ));
        }

        return_multiple_errors(errors)
    }
}

///  Windows™ PE Section Type
/// The Windows PE Section type specifies metadata about a PE file section
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ioapwyd8oimw>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPESectionType {
    /// Specifies the name of the section.
    pub name: String,
    /// Specifies the size of the section, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub size: Option<u64>,
    /// Specifies the calculated entropy for the section, as calculated using the Shannon algorithm <https://en.wiktionary.org/wiki/Shannon_entropy>. The size of each input character is defined as a byte, resulting in a possible range of 0 through 8.
    pub entropy: Option<ordered_float<f32>>,
    /// Specifies any hashes computed over the section.
    pub hashes: Option<Hashes>,
}

impl Stix for WindowsPESectionType {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(size) = &self.size {
            size.stix_check()
        } else {
            Ok(())
        }
    }
}

/// Possible extensions for NetworkTraffic SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum NetworkTrafficExtensions {
    IcmpExt(IcmpExtension),
    HttpRequestExt(HttpRequestExtension),
    SocketExt(SocketExtenion),
    TcpExt(TcpExtension),
}

/// The ICMP extension specifies a default extension for capturing network traffic properties specific to ICMP.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_ozypx0lmkebv>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpExtension {
    /// Specifies the ICMP type byte.
    pub icmp_type_hex: String,
    /// Specifies the ICMP code byte.
    pub icmp_code_hex: String,
}

impl Stix for IcmpExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();
        let icmp_type_hex = &self.icmp_type_hex;
        if hex::decode(icmp_type_hex).is_err() {
            errors.push(Error::ParseHexError(
                "icmp_type_hex -- ".to_string() + icmp_type_hex,
            ))
        }
        let icmp_code_hex = &self.icmp_code_hex;
        if hex::decode(icmp_code_hex).is_err() {
            errors.push(Error::ParseHexError(
                "icmp_code_hex -- ".to_string() + icmp_code_hex,
            ))
        }

        return_multiple_errors(errors)
    }
}

/// The HTTP request extension specifies a default extension for capturing network traffic properties specific to HTTP requests.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_b0e376hgtml8>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestExtension {
    /// Specifies the HTTP method portion of the HTTP request line, as a lowercase string.
    pub request_method: String,
    /// Specifies the value (typically a resource path) portion of the HTTP request line.
    pub request_value: String,
    /// Specifies the HTTP version portion of the HTTP request line, as a lowercase string.
    pub request_version: Option<String>,
    /// Specifies all of the HTTP header fields that may be found in the HTTP client request, as a dictionary.
    pub request_header: Option<StixDictionary<String>>,
    /// Specifies the length of the HTTP message body, if included, in bytes.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub message_body_length: Option<u64>,
    /// Specifies the data contained in the HTTP message body, if included.
    pub message_body_data_ref: Option<Identifier>,
}

impl Stix for HttpRequestExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(message_body_length) = &self.message_body_length {
            add_error(&mut errors, message_body_length.stix_check());
        }
        if let Some(message_body_data_ref) = &self.message_body_data_ref {
            message_body_data_ref.stix_check()?;
            if message_body_data_ref.get_type() != "artifact" {
                errors.push(Error::ValidationError(format!(
                    "message_body_data_ref {} must be of type 'artifact'.",
                    message_body_data_ref.get_type()
                )));
            }
        }
        if let Some(request_header) = &self.request_header {
            add_error(&mut errors, request_header.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// The Network Socket extension specifies a default extension for capturing network traffic properties associated with network sockets.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_8jamupj9ubdv>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketExtenion {
    /// Specifies the address family (AF_*) that the socket is configured for.
    pub address_family: Option<String>,
    /// Specifies whether the socket is in blocking mode.
    pub is_blocking: Option<bool>,
    /// Specifies whether the socket is in listening mode.
    pub is_listening: Option<bool>,
    /// Specifies any options (e.g., SO_*) that may be used by the socket, as a dictionary.
    pub options: Option<StixDictionary<DictionaryValue>>,
    /// Specifies the type of the socket.
    pub socket_type: Option<String>,
    /// Specifies the socket file descriptor value associated with the socket, as a non-negative integer.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub socket_descriptor: Option<u64>,
    /// Specifies the handle or inode value associated with the socket.
    #[serde(default, deserialize_with = "as_opt_u64")]
    pub socket_handle: Option<u64>,
}

impl Stix for SocketExtenion {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(socket_descriptor) = &self.socket_descriptor {
            add_error(&mut errors, socket_descriptor.stix_check());
        }
        if let Some(address_family) = &self.address_family {
            if NetworkSocketAddressFamilyEnum::iter().all(|x| x.as_ref() != address_family) {
                errors.push(Error::ValidationError(format!(
                        "The values of this property MUST come from the network-socket-address-family-enum enumeration. {}.",
                        address_family,
                    )));
            }
        }
        if let Some(socket_type) = &self.socket_type {
            if NetworkSocketTypeEnum::iter().all(|x| x.as_ref() != socket_type) {
                errors.push(Error::ValidationError(format!(
                        "The values of this property MUST come from the network-socket-type-enum enumeration. {}.",
                        socket_type,
                    )));
            }
        }
        if let Some(options) = &self.options {
            add_error(&mut errors, options.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// The TCP extension specifies a default extension for capturing network traffic properties specific to TCP.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_k2njqio7f142>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpExtension {
    /// Specifies the source TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property).
    pub src_flags_hex: Option<String>,
    /// Specifies the destination TCP flags, as the union of all TCP flags observed between the start of the traffic (as defined by the start property) and the end of the traffic (as defined by the end property).
    pub dst_flags_hex: Option<String>,
}

impl Stix for TcpExtension {
    fn stix_check(&self) -> Result<(), Error> {
        if let Some(src_flags_hex) = &self.src_flags_hex {
            warn!("If the start and end times of the traffic are not specified, src_flags_hex {} SHOULD be interpreted as the union of all TCP flags observed over the entirety of the network traffic being reported upon.",src_flags_hex);
        }
        if let Some(dst_flags_hex) = &self.dst_flags_hex {
            warn!("If the start and end times of the traffic are not specified, dst_flags_hex {} SHOULD be interpreted as the union of all TCP flags observed over the entirety of the network traffic being reported upon.",dst_flags_hex);
        }
        let mut errors = Vec::new();
        if let Some(src_flags_hex) = &self.src_flags_hex {
            if hex::decode(src_flags_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "src_flags_hex -- ".to_string() + src_flags_hex,
                ))
            }
        }
        if let Some(dst_flags_hex) = &self.dst_flags_hex {
            if hex::decode(dst_flags_hex).is_err() {
                errors.push(Error::ParseHexError(
                    "dst_flags_hex -- ".to_string() + dst_flags_hex,
                ))
            }
        }

        return_multiple_errors(errors)
    }
}

/// Possible extensions for Process SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum ProcessExtensions {
    WindowsProcessExt(WindowsProcessExtension),
    WindowsServiceExt(WindowsServiceExtension),
}

/// The Windows Process extension specifies a default extension for capturing properties specific to Windows processes.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oyegq07gjf5t>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProcessExtension {
    /// Specifies whether Address Space Layout Randomization (ASLR) is enabled for the process.
    pub aslr_enabled: Option<bool>,
    /// Specifies whether Data Execution Prevention (DEP) is enabled for the process.
    pub dep_enabled: Option<bool>,
    /// Specifies the current priority class of the process in Windows.
    pub priority: Option<String>,
    /// Specifies the Security ID (SID) value of the owner of the process.
    pub owner_sid: Option<String>,
    /// Specifies the title of the main window of the process.
    pub window_title: Option<String>,
    /// Specifies the STARTUP_INFO struct used by the process, as a dictionary.
    pub startup_info: Option<StixDictionary<Vec<String>>>,
    /// Specifies the Windows integrity level, or trustworthiness, of the process.
    pub integrity_level: Option<String>,
}
impl Stix for WindowsProcessExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(priority) = &self.priority {
            if !priority.ends_with("_CLASS") {
                warn!(
                    "priority SHOULD be a string that ends in '_CLASS' {}.",
                    priority,
                );
            }
        }
        if let Some(integrity_level) = &self.integrity_level {
            if WindowsIntegrityEnum::iter()
                .all(|x| x.as_ref() != integrity_level.to_case(Case::Kebab))
            {
                errors.push(Error::ValidationError(format!(
                        "The values of integrity_level MUST come from the windows-integrity-level-enum enumeration. {}.",
                        integrity_level,
                    )));
            }
        }

        if let Some(startup_info) = &self.startup_info {
            add_error(&mut errors, startup_info.stix_check());
        }

        return_multiple_errors(errors)
    }
}

/// Windows Service Extension
///
/// The Windows Service extension specifies a default extension for capturing properties specific to Windows services.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_lbcvc2ahx1s0>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsServiceExtension {
    /// Specifies the name of the service.
    pub service_name: Option<String>,
    /// Specifies the descriptions defined for the service.
    pub descriptions: Option<Vec<String>>,
    /// Specifies the display name of the service in Windows GUI controls.
    pub display_name: Option<String>,
    /// Specifies the name of the load ordering group of which the service is a member.
    pub group_name: Option<String>,
    /// Specifies the start options defined for the service.
    pub start_type: Option<String>,
    /// Specifies the DLLs loaded by the service, as a reference to one or more File objects.
    pub service_dll_refs: Option<Vec<Identifier>>,
    /// Specifies the type of the service.
    pub service_type: Option<String>,
    /// Specifies the current status of the service.
    pub service_status: Option<String>,
}
impl Stix for WindowsServiceExtension {
    fn stix_check(&self) -> Result<(), Error> {
        let mut errors = Vec::new();

        if let Some(service_dll_refs) = &self.service_dll_refs {
            for sdr in service_dll_refs {
                if sdr.get_type() != "file" {
                    errors.push(Error::ValidationError(
                        "service_dll_refs must be of type 'file'.".to_string(),
                    ));
                }
            }
        }
        if let Some(start_type) = &self.start_type {
            if WindowsServiceStartTypeEnum::iter()
                .all(|x| x.as_ref() != start_type.to_case(Case::Kebab))
            {
                errors.push(Error::ValidationError(format!(
                        "The values of start_type MUST come from the windows-service-start-type-enum enumeration.. {}.",
                        start_type,
                    )));
            }
        }
        if let Some(service_status) = &self.service_status {
            if WindowsServiceStatusEnum::iter()
                .all(|x| x.as_ref() != service_status.to_case(Case::Kebab))
            {
                errors.push(Error::ValidationError(format!(
                        "The values of service_status MUST come from the windows-service-status-enum enumeration.. {}.",
                        service_status,
                    )));
            }
        }
        if let Some(service_type) = &self.service_type {
            if WindowsServiceTypeEnum::iter()
                .all(|x| x.as_ref() != service_type.to_case(Case::Kebab))
            {
                errors.push(Error::ValidationError(format!(
                        "The values of service_type MUST come from the windows-service-type-enum enumeration.. {}.",
                        service_type,
                    )));
            }
        }

        return_multiple_errors(errors)
    }
}

/// Possible extensions for UserAccount SCOs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, AsRefStr, EnumIter)]
#[serde(untagged)]
#[strum(serialize_all = "kebab-case")]
pub enum UserAccountExtensions {
    UnixAccountExt(UnixAccountExtension),
}

/// The UNIX account extension specifies a default extension for capturing the additional information for an account on a UNIX system.
///
/// An object using the UNIX Account Extension **MUST** contain at least one property from this extension.
///
/// For more information see <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_hodiamlggpw5>
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixAccountExtension {
    /// Specifies the primary group ID of the account.
    #[serde(default, deserialize_with = "as_opt_i64")]
    pub gid: Option<i64>,
    /// Specifies a list of names of groups that the account is a member of.
    pub groups: Option<Vec<String>>,
    /// Specifies the home directory of the account.
    pub home_dir: Option<String>,
    /// Specifies the account’s command shell.
    pub shell: Option<String>,
}

impl Stix for UnixAccountExtension {
    fn stix_check(&self) -> Result<(), Error> {
        if self.gid.is_none()
            && self.groups.is_none()
            && self.home_dir.is_none()
            && self.shell.is_none()
        {
            return Err(Error::ValidationError(
                "At least one field must be set in UnixAccountExtension".to_string(),
            ));
        }
        if let Some(gid) = &self.gid {
            gid.stix_check()?;
        }
        Ok(())
    }
}
