# Commands for backup.yml & restore_from_backup.yml 
---
# Backup 

**source_dir** is the directory you want to backup. e.g /var/www/ \
**backup_dir** is the location where you want the directory. e.g /opt/memento 
```
ansible-playbook -e source_dir=/var/www -e backup_dir=/opt/memento ./backup.yml
```
Your backup will be stored on the machine!
---
# Restore from backup 

**backup_dir** is the directory that holds the backup you want. e.g /opt/memento \
**restore_dir** is the location where you want the directory to be restored. e.g /var/www \
**source_name** is the name of the file/directory you want to be backed up. e.g /var/www/apache2
```
ansible-playbook -e backup_dir=/opt/memento -e restore_dir=/var/www -e source_name=/var/www/apache2 ./restore_from_backup.yml 
```
