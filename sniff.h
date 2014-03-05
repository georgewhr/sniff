struct ctl_mesg{
  __u16 port_listen;
  __u32 d_addr;
  short set_port_flag;
  short kick_off_flag;
  short post_hook_start_monitor;
};


struct buff_ctl{
  spinlock_t buff_lock;
  char *buff;
  unsigned int length;
};

