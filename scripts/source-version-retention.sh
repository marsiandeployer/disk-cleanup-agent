#!/bin/sh

# Keep the active source install and one rollback target. Only installer-owned
# real directories in the source-* namespace are eligible for removal.
activate_source_version() {
  prefix=$1
  new_target=$2
  current_path=$prefix/current
  previous_path=$prefix/previous
  old_target=

  if [ -L "$current_path" ]; then
    old_target=$(readlink -- "$current_path") || return 1
    case "$old_target" in
      versions/source-*)
        old_dir=$prefix/$old_target
        if [ ! -d "$old_dir" ] || [ -L "$old_dir" ]; then old_target=; fi
        ;;
      *) old_target= ;;
    esac
  fi

  if [ -n "$old_target" ] && [ "$old_target" != "$new_target" ]; then
    previous_tmp=$prefix/.previous.$$
    ln -s -- "$old_target" "$previous_tmp" || return 1
    mv -Tf -- "$previous_tmp" "$previous_path" || return 1
  fi

  current_tmp=$prefix/.current.$$
  ln -s -- "$new_target" "$current_tmp" || return 1
  mv -Tf -- "$current_tmp" "$current_path" || return 1
}

source_version_in_use() {
  version_dir=$1
  proc_root=$2
  version_real=$(readlink -f -- "$version_dir") || return 2
  for process_dir in "$proc_root"/[0-9]*; do
    [ -L "$process_dir/exe" ] || continue
    process_exe=$(readlink -- "$process_dir/exe" 2>/dev/null) || continue
    case "$process_exe" in
      "$version_real"/*) return 0 ;;
    esac
  done
  return 1
}

prune_source_versions() {
  prefix=$1
  proc_root=${2:-/proc}
  current_target=
  previous_target=

  # Without the process table, an older executable may still be loading its
  # model or shared libraries. Leave every version in place in that case.
  if [ ! -L "$proc_root/self/exe" ]; then
    printf '%s\n' 'disk-cleanup-agent: process visibility unavailable; keeping older source versions' >&2
    return 0
  fi

  if [ -L "$prefix/current" ]; then
    current_target=$(readlink -- "$prefix/current") || return 1
    case "$current_target" in versions/source-*) ;; *) current_target= ;; esac
  fi
  if [ -L "$prefix/previous" ]; then
    previous_target=$(readlink -- "$prefix/previous") || return 1
    case "$previous_target" in versions/source-*) ;; *) previous_target= ;; esac
  fi

  for version_dir in "$prefix"/versions/source-*; do
    [ -d "$version_dir" ] || continue
    [ ! -L "$version_dir" ] || continue
    target=versions/${version_dir##*/}
    [ "$target" = "$current_target" ] && continue
    [ "$target" = "$previous_target" ] && continue
    if source_version_in_use "$version_dir" "$proc_root"; then
      continue
    else
      result=$?
      if [ "$result" -ne 1 ]; then
        printf '%s\n' 'disk-cleanup-agent: cannot verify an older executable; keeping it' >&2
        continue
      fi
    fi
    rm -rf -- "$version_dir"
  done
}
