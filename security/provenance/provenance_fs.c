#include <linux/sched.h>
#include <linux/proc_fs.h>/* Necessary because we use the proc fs */
#include <linux/provenance.h>
/* daveti: for IRQ and SEQ */
#include <linux/hardirq.h>
#include <linux/seq_file.h>


static int debug = 1;

/* daveti: comment it out
static ssize_t
read_proc(struct file *file,char __user *buf, size_t count,loff_t *offp ) 
{
  char *data = (char *)PDE(file->f_path.dentry->d_inode)->data;
  long len;

  if(!(data)){
    pr_info("Provenance FS: Null data");
    return 0;
  }

  len = strlen(data);

  if(count > len)
    count = len;

  pr_info("Provenance FS: Attempting to read (%d) bytes of (%s) from file <%s>.\n",
	 (int)count,data,file->f_path.dentry->d_name.name);

  if(!copy_to_user(buf,data,count)){
    //pr_info("Provenance FS: User buffer is now (%s). Return val is (%d)\n",buf,(int)count);
    return count;
  } else {
	pr_err("Provenance FS: Error - copy_to_user failed\n");
  }

  return 0;
}
*/

static int provenance_cred_proc_show(struct seq_file *m, void *v)
{
	unsigned long *cred_id = m->private;
	seq_printf(m, "%lu\n", *cred_id);
	return 0;
}

static int provenance_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, provenance_cred_proc_show, PDE(inode)->data);
}

static const struct file_operations provenance_fs_fops = {
  .open		= provenance_proc_open,
  .read		= seq_read,
  .release	= single_release,
};

static struct proc_dir_entry *provenance_fs_prov_dir;
static struct proc_dir_entry *provenance_fs_creds_dir;

int __init provenance_fs_init(void)
{
	provenance_fs_prov_dir = proc_mkdir("provenance",
					    NULL);
	if (IS_ERR(provenance_fs_prov_dir)){
		pr_err("Provenance FS: ERROR - failed to create securityfs dir\n");
            	goto out;
	}

	provenance_fs_creds_dir = proc_mkdir("creds",provenance_fs_prov_dir);

	if (IS_ERR(provenance_fs_creds_dir)){
		pr_err("Provenance FS: ERROR - failed to create securityfs dir\n");
            	goto out;
	}

	pr_info("Provenance FS: Successfully mounted filesystem directory\n");
	return 0;

 out:
	if(provenance_fs_creds_dir)
	  remove_proc_entry("creds", provenance_fs_prov_dir);

	if(provenance_fs_prov_dir)
	  remove_proc_entry("provenance", NULL);

	return -1;
}

/* fs_initcall(provenance_fs_init); */

int provenance_fs_publish_cred(pid_t pid, unsigned long cred_id)
{
  struct proc_dir_entry * new_entry;
  struct task_struct * target;
  int max_len, ret;
  char *filename, *cred_str;

  return 0;

  /* daveti: check for IRQ ctx */
  if (in_interrupt()){
    printk(KERN_ERR "Provenance FS: In interrupt (%s)\n",__func__);
    return 0;
  }

  ret = 0;
  max_len = 32;
  filename = kzalloc(max_len * sizeof(char), GFP_ATOMIC);
  cred_str = kzalloc(max_len * sizeof(char), GFP_ATOMIC);

  snprintf(filename, max_len * sizeof(char), "%d",pid);
  snprintf(cred_str, max_len * sizeof(char), "%lu",cred_id);

  /* Precaution: Attempt to remove proc entry */
  /* I am not sure if there is a better way to "test" if it exists */
  //remove_proc_entry(filename,provenance_fs_creds_dir);

  /* Create new proc entry */  
  /*
  new_entry = create_proc_entry(filename,
				0777,
				provenance_fs_creds_dir);
  */

  printk(KERN_ERR "Provenance FS: Inserting %s into %s.\n", cred_str, filename); 

  /*
  // Get the target task
  target = find_task_by_vpid(pid);
  if (!target) {
	pr_err("Provenance FS: Error - no task found for pid [%i]\n", pid);
	goto ENTRY_OUT;
  }

  // Save the cred ID
  target->cred_id = cred_id;
  */

  /* Pop up the data */
  new_entry = proc_create_data(filename,
			       0,
			       provenance_fs_creds_dir,
			       &provenance_fs_fops,
			       &target->cred_id);
  
  if (IS_ERR(new_entry)){
    pr_err("Provenance FS: ERROR - failed to create file\n");
    ret = -EINVAL;
    goto ENTRY_OUT;
  }

ENTRY_OUT:
  kfree(filename);
  kfree(cred_str);
  return ret;
}

int provenance_fs_unpublish_cred(pid_t pid)
{
  int max_len;
  char *filename;

  return 0;

  /* daveti: check for IRQ ctx */
  if (in_interrupt()){
    printk("Provenance FS: In Interrupt (%s)\n",__func__);
    return 0;
  }

  max_len = 32;
  filename = kzalloc(max_len * sizeof(char), GFP_ATOMIC);
  snprintf(filename, max_len * sizeof(char), "%d", pid);

  remove_proc_entry(filename,provenance_fs_creds_dir);

  kfree(filename);

  
  if (debug)
	pr_info("daveti: Debug - done [%s], pid [%d]\n", __func__, pid);


  return 0;
}

