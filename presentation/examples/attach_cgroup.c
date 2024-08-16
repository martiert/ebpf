int fd = open(cgroup_directory_path,
        O_DIRECTORY|O_RDONLY);
bpf_program__attach_cgroup(
        skeleton->progs.egress, fd);
bpf_program__attach_cgroup(
        skeleton->progs.ingress, fd);
