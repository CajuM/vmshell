ENTRY(_entry)

SECTIONS {
    .stage1 : {
      _stage1_start = .;
      *(.entry)
      *(.text)
      *(.text.*)
      *(.data)
      *(.data.*)
      *(.bss)
      *(.bss.*)
      *(.rodata)
      *(.rodata.*)
      _stage1_end = .;
    }

    /DISCARD/ : {
      *(.eh_frame)
      *(.comment)
    }
}
