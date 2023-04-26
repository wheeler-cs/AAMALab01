from datetime import datetime, timezone
from sys import argv
from typing import List
import lief


def main(pe_name:str = ""):
    binary = lief.parse (pe_name)
    get_input = True
    while get_input == True:
        print ("1) General PE Information")
        print ("2) COFF Header")
        print ("3) Optional Header")
        print ("4) Load Configuration")
        print ("5) Library Imports")
        print ("6) .text Section")
        print ("7) Quit")
        print()
        user_input = int (input ("PE> "))
        if user_input   == 1:
            read_pe_information (binary)
        elif user_input == 2:
            read_coff_header (binary)
        elif user_input == 3:
            read_optional_header (binary)
        elif user_input == 4:
            read_load_config (binary)
        elif user_input == 5:
            read_library_imports (binary)
        elif user_input == 6:
            read_text_section (binary)
        elif user_input == 7:
            get_input = False
        print()


def read_pe_information (parsed_binary: lief.PE.Binary = None) -> None:
    print ()
    # Executable file name
    pe_name = parsed_binary.name
    # Size of executable
    pe_size = parsed_binary.optional_header.sizeof_image
    # Virtual size of executable
    pe_virtual_size = parsed_binary.virtual_size
    # Address of New Executable header
    pe_e_lfanew = parsed_binary.dos_header.addressof_new_exeheader
    # Min, avg, and max section entropy values
    section_entropies: List[int] = []
    for s in parsed_binary.sections:
        section_entropies.append (s.entropy)
    pe_min_entropy = min (section_entropies)
    pe_avg_entropy = (sum (section_entropies) / len (section_entropies))
    pe_max_entropy = max (section_entropies)
    # Print information about portable executable
    print ("Executable Name | " + pe_name)
    print ("Executable Size | " + str (pe_size) + " bytes")
    print ("Virtual PE Size | " + str (pe_virtual_size) + " bytes")
    print ("New Head. Start | " + str (hex (pe_e_lfanew)))
    print ("Minimum Entropy | " + str ( format (pe_min_entropy, ".4f")))
    print ("Average Entropy | " + str ( format (pe_avg_entropy, ".4f")))
    print ("Maximum Entropy | " + str ( format (pe_max_entropy, ".4f")))


def read_coff_header (parsed_binary: lief.PE.Binary = None) -> None:
    print ()
    # Target machine architecture
    target_machine = parsed_binary.header.machine.name
    # Number of sections in executable
    section_quant = parsed_binary.header.numberof_sections
    # Time-date stamp of executable
    timestamp = datetime.fromtimestamp (parsed_binary.header.time_date_stamps).strftime ('%Y-%m-%d %H:%M:%S')
    # Symbol table pointer
    symtable_ptr = parsed_binary.header.pointerto_symbol_table
    # Number of symbols
    symbol_quant = parsed_binary.header.numberof_symbols
    # Optional header size
    oheader_size = parsed_binary.header.sizeof_optional_header
    # Characteristics of executable
    characteristics = parsed_binary.header.characteristics_list
    #Print COFF information
    print (" Target Architecture | " + target_machine)
    print ("  Number of Sections | " + str (section_quant))
    print (" Embedded  Timestamp | " + str (timestamp))
    print ("Symbol Table Pointer | " + str (hex (symtable_ptr)))
    print ("   Number of Symbols | " + str (symbol_quant))
    print ("Optional Header Size | " + str (oheader_size) + " bytes")
    print ("PE Characterisitics... ")
    for c in characteristics:
        print ("    (" + str ( hex (c.value)) + ") " + c.name)


def read_optional_header (parsed_binary: lief.PE.Binary = None) -> None:
    print ()
    # Magic number
    magic = parsed_binary.optional_header.magic.name
    # Major linker version
    linker_majver = parsed_binary.optional_header.major_linker_version
    # Minor linker version
    linker_minver = parsed_binary.optional_header.minor_linker_version
    # Code size
    code_size = parsed_binary.optional_header.sizeof_code
    # Size of initialized data
    initialized_size = parsed_binary.optional_header.sizeof_initialized_data
    # Size of uninitialized data
    uninitialized_size = parsed_binary.optional_header.sizeof_uninitialized_data
    # Code's base
    code_base = parsed_binary.optional_header.baseof_code
    # DLL properties
    dll_properties = parsed_binary.optional_header.dll_characteristics
    # Image's base
    image_base = parsed_binary.optional_header.imagebase
    # File byte alignment
    byte_alignment = parsed_binary.optional_header.file_alignment
    # Image size
    image_size = parsed_binary.optional_header.sizeof_image
    # Header size
    header_size = parsed_binary.optional_header.sizeof_headers
    # Stack reserve size
    stackres_size = parsed_binary.optional_header.sizeof_stack_reserve
    # Required subsystem
    subsystem = parsed_binary.optional_header.subsystem.name
    # Major subsystem version
    subsys_majver = parsed_binary.optional_header.major_subsystem_version
    # Minor subsystem version
    subsys_minver = parsed_binary.optional_header.minor_subsystem_version
    # Major OS version
    os_majver = parsed_binary.optional_header.major_operating_system_version
    # Minor OS version
    os_minver = parsed_binary.optional_header.minor_operating_system_version
    # Print optional header information
    print ("              Magic Number | " + str (magic))
    print ("            Linker Version | " + str (linker_majver) + "." + str (linker_minver))
    print ("              Size of Code | " + str (code_size) + " bytes" )
    print ("     Initialized Data Size | " + str (initialized_size) + " bytes")
    print ("   Uninitialized Data Size | " + str (uninitialized_size) + " bytes")
    print ("     Location of Code Base | " + str (hex (code_base)))
    print ("        DLL Property Flags | " + str (hex (dll_properties)))
    print ("    Location of Image Base | " + str (hex (image_base)))
    print ("      Chunk Byte Alignment | " + str (byte_alignment) + " bytes")
    print ("             Size of Image | " + str (image_size) + " bytes")
    print ("            Size of Header | " + str (header_size) + " bytes")
    print ("   Resevered Size of Stack | " + str (stackres_size) + " bytes")
    print ("Required Windows Subsystem | " + str (subsystem) + " (v" + str (subsys_majver) + "." + str (subsys_minver) + ")")
    #print ("  Required Windows Version | " + str (os_majver) + "." + str (os_minver)) # Potentially the same as subsys version


def read_sections (parsed_binary: lief.PE.Binary = None) -> None:
    print ()
    for section in parsed_binary.sections:
        # Name of the section
        name = section.fullname
        # Calculated entropy value of section
        entropy = section.entropy
        # Characteristics of section
        characteristics = section.characteristics_lists
        print()
        print (" Section Name | " + name)
        print ("Entropy Value | " + str ( format (entropy, ".4f")))
        print ("Characterisitics... ")
        for c in characteristics:
            print ("    " + c.name)


def read_load_config (parsed_binary: lief.PE.Binary = None) -> None:
    print()
    if parsed_binary.has_configuration:
        # Security cookie of load configuration directory
        security_cookie = parsed_binary.load_configuration.security_cookie
        print ("Security Cookie | " + str (security_cookie))
    else:
        print ("Security Cookie | None")


def read_library_imports (parsed_binary: lief.PE.Binary = None) -> None:
    print()
    for i in parsed_binary.imports:
        # File name of import
        import_name = i.name
        # Functions imported from file
        import_funcs = i.entries
        print()
        print ("Import Name | " + str (import_name))
        for f in import_funcs:
            if not f.is_ordinal:
                print ("    " + f.name)
                

def read_text_section (parsed_binary: lief.PE.Binary = None) -> None:
    # Add important attributes here
    pass



if __name__ == "__main__":
    main(argv[1])