require 'puppet/util/checksums'

Puppet::Type.newtype(:exec_noop_out) do
  
  include Puppet::Util::Diff
  include Puppet::Util::Checksums
  include Puppet::Util::Execution
  require 'fileutils'
  require 'etc'

  @doc = <<-'EOT'
    Run an auditable exec command and output any results in noop mode
    or apply changes in non-noop mode.

    NB. Will transform any params representing files
        to temp paths when run in noop mode!

    Example:

    exec_noop_out { 'audit_script.rb':
      deploy_path   => "${home}/current/utilities/links",
      owner         => $app_user,
      script_name   => "audit_script.rb",
      params        => "${params} apply_changes",
      noop_params   => "${params}",
      files_content => { 'audit_script.rb'          => $audit_script_content,
                         'lib/alib.rb'              => $alib_content,
                         'audit_script.cfg'         => $audit_script_cfg,
                       },
      environment   => ["ORACLE_HOME=${ora_home}",
                        "TNS_ADMIN=${tns_admin}"],
      changes_ret   => 5,
      funcerr_ret   => 10,
    }
  EOT

  newparam(:name) do
    desc 'An arbitrary name used as the identity of the resource.'

    isnamevar
  end

  newparam(:owner) do
    desc 'The owner of the files and the context to run the commands'
  end

  newparam(:deploy_path) do
    desc 'Path of directory to deploy files to'

    validate do | value |
      if !(value =~ /^\//)
        raise(ArgumentError, "Invalid deploy_path (#{value}). Must be absolute")
      end
    end
  end

  newparam(:files_content) do
    desc 'A hash with keys for relative file names to deploy and ' +
         'with values set to the file content'

    validate do |value|
      # Parse the structure and ensure it's OK
      if !value.is_a?(Hash)
        raise(ArgumentError, 'Invalid value for file_content. ' +
                             'Expecting hash of file names and content.')
      end
      value.each do | file_path, content |
        # Check the key is a valid relative path:
        if file_path =~ /^\//
          raise(ArgumentError, "Invalid path (#{file_path}). Paths must be relative (to script).")
        end
        if (content.length < 1)
          raise(ArgumentError, 'Expecting more content than that.')
        end
      end
    end
  end

  newparam(:script_name) do
    desc 'The name of the script to deploy'

    validate do |value|
      if resource[:files_content][value.to_s] == nil
        raise(ArgumentError, "Must include '#{value}' in files_content parameter.")
      end
    end
  end

  newparam(:timeout) do
    desc 'Time to allow command to run for'

    defaultto 40

    validate do |value|
      unless value.to_s =~ /^\d+$/
        raise ArgumentError, "Timeout must be an integer not:'#{value}'"
      end
    end
  end

  newparam(:environment) do
    desc 'Environment variables to set before running script'

    defaultto []

    validate do |value|
      value.to_a.each do |env_str|
        unless env_str =~ /\w+=/
          raise ArgumentError, "Invalid environment setting '#{env_str}'"
        end
      end
    end
  end

  newparam(:noop_params) do
    desc 'The set of parameters to provide to a script when auditing (NO changes)'

    munge do |value|
      value = [value] unless value.is_a? Array
      value
    end
  end

  newparam(:apply_params) do
    desc 'The set of parameters to provide to a script when APPLYING CHANGES'

    validate do |value|
      if resource[:noop_params].join(' ') == value.join(' ')
        raise  ArgumentError, "Can NOT set parameter apply_params to the same as noop_params."
      end
      value
    end

    munge do |value|
      value = [value] unless value.is_a? Array
      value
    end
  end

  newparam(:changes_ret) do
    desc "The return code(s) to indicate 'changes required'"

    validate do |value|
      resource.validate_ret_code(value)
    end

    munge do |value|
      value = [value] unless value.is_a? Array 
    end
  end

  newparam(:warnings_ret) do
    desc "The return code(s) indicate a functional warning"

    validate do |value|
      resource.validate_ret_code(value)
    end
    
    munge do |value|
      value = [value] unless value.is_a? Array 
    end
  end

  newproperty(:files) do
    desc 'The files to be deployed as represented by ' +
         'the file_content KEYS param (is) AND their VALUES (should)'
    
    attr_reader :file_changes, :changes, :intented_md5

    defaultto :no_changes

    validate do |value|
      unless value == :no_changes
        raise(Puppet::Error, "Can't set the run property from puppet manifest. It is for displaying output")
      end
    end

    def retrieve
      @changes = false
      resource[:files_content].each do | file_name, intended_content |
        file_path = File.join(resource[:deploy_path], file_name)
        current_md5, current_content = resource.content_retrieve(file_path, true)

        @file_changes = Hash.new if !@file_changes
        @intended_md5 = Hash.new if !@intended_md5
        intended_md5 = resource.md5_content(intended_content)
        @intended_md5[file_path] = intended_md5
        if current_md5 != intended_md5
          @changes = true 
          if current_md5 == :absent
            @file_changes[file_path] = :absent
          else
            @file_changes[file_path] = true
          end
        end
      end
      ret = :no_changes
      if @changes
        ret = :changes_required
      end
      ret
    end

    def insync?(is)
      result = true
      if (is.to_sym == :changes_required)
        result = false
        # Display any diffs required:
        resource[:files_content].each do | file_name, intended_content |
          file_path = File.join(resource[:deploy_path], file_name)
          if Puppet[:show_diff] && @file_changes[file_path]
            if (@file_changes[file_path] != :absent)
              resource.content_diff(file_path, intended_content, 'intended-content-')
            else
              if Puppet[:noop]
                notice("#{file_path} current_value :absent, should be md5(#{@intended_md5[file_path]}) (noop)")
              end
            end
          end
        end
      end
      result
    end

    def sync
      resource.exist?
    end
    
    def flush
      resource.save_files(resource[:deploy_path])
      resource[:files_content].each do | file_name, intended_content |
        file_path = File.join(resource[:deploy_path], file_name)
        if (@file_changes[file_path])
          notice ("#{file_path} written as md5(#{@intended_md5[file_path]})")
        end
      end
    end
  end

  newproperty(:exec) do

    desc "Property to actually run the script - not set by user"

    attr_accessor :script_src, :script_changed, :audit_output, :do_run, :tmp_path_map

    defaultto :run_no_changes
    
    validate do |value|
      unless value == :run_no_changes
        raise(Puppet::Error, "Can't set the run property from puppet manifest. It is for displaying output")
      end
    end

    def retrieve
      # Detect a change required (audit failed) exit code!
      @do_run = false
      changes_required = false

      # Keep track of any transformed file names:
      @tmp_full_path_map = Hash.new
      self.mktmpdir() do |dir|
        # Save the script and config temporarily:
        resource.save_files(dir)

        # Run the script in noop mode:
        script_tmp_path = File.join(dir, resource[:script_name])
        changes_required, @audit_output = run_get_output(script_tmp_path,
                                                         false)
      end
      if changes_required
        @do_run = true
        return :changes_required
      else
        return :run_no_changes
      end
    end

    def insync?(is)
      # Decide if no changes are required
      if (is.to_sym == :absent) || (is.to_sym == :changed) || (is.to_sym == :changes_required)
        result = false
        # Report on all changes required here if noop
        notice("Changes required:\n\n#{@audit_output}") if Puppet[:noop]
      else
        result = true
      end
      result
    end

    def sync
      return_event = resource.exist?

      # The flush on the parent will actually run the script
      # as this is the only place we can garentee all data is
      # present at the final locations
      
      return_event
    end

    def flush
      # This will be called last and ONLY when NOT --noop :)
      if @do_run
        # Only run if changes detected
        output = ''
        changes_required = false
        script_path = File.join(resource[:deploy_path], resource[:script_name])
        changes_required, output = run_get_output(script_path, true)
        notice("Changes made:\n\n#{output}")
      end
    end

    def mktmpdir()
      Dir.mktmpdir("puppet-tmp-noop-exec-out-") do |dir|
        if Puppet[:debug]
          new_dir = "#{dir}-keep"
          FileUtils.cp_r(dir, new_dir)
        else
          new_dir = dir
        end
        File.chmod(0755, new_dir)
        resource.chown(new_dir)
        yield new_dir
      end
    end

    def withenv(hash)
      saved = ENV.to_hash
      hash.each do |name, val|
        ENV[name.to_s] = val
      end

      yield
      # Remove any variable explicitly set
      hash.each do |name, val|
        ENV.delete(name.to_s)
      end
      # Restore any variable's saved
      saved.each do |name, val|
        ENV[name] = val
      end
    end

    def run_get_output(script,
                       apply_changes)

      # Set the environment here:
      run_env = Hash.new
      vars = resource[:environment].each do |env|
        env_values = env.split('=')
        run_env[env_values[0]] = env_values[1]
      end
      if apply_changes
        params = resource[:apply_params]
      else
        params = resource[:noop_params]
      end
      deploy_path = File.dirname(script)
      # Transform any parameters to NEW TEMP location!
      params_str = ''
      params.to_a.each do |param|
        case param
        when /^\//
          # Replace any literal full paths that
          # contain the deployment path AND
          # have a sub string of one of the managed
          # files!
          new_param = param
          resource[:files_content].keys.each do |file|
            if param.include?(file)
              new_param = File.join(deploy_path, file)
              break
            end
          end
        when resource[:files_content].keys.include?(param)
          # Make any other managed file params complete
          new_param = File.join(dir, param)
        else
          new_param = param
        end
        params_str = "#{params_str} #{new_param}"
      end

      command = "#{script} #{params_str}"
      status = 0
      output = ''
      # This should never take longer than a few seconds...
      Timeout::timeout(resource[:timeout]) do
        # Using own withenv as SUIDManager doesn't cpature output 
        # after all envs reset on SLES when run under sudo.
        withenv(run_env) do
          output, status = Puppet::Util::SUIDManager.run_and_capture("su #{resource[:owner]} -c '#{command}'")
        end
      end
      
      # The shell returns 127 if the command is missing.
      changes_required = false
      case status.exitstatus.to_s
      when "127"
        raise(Puppet::Error, "#{resource[:name]}: Command not found: '#{command}'")
      when "0"
        # Successfuly applied / audited changes OR no changes required
      when *resource[:changes_ret]
        if apply_changes
          raise(Puppet::Error, "#{resource[:name]}: Unexpected return when apply_changes used (#{status.exitstatus}): '#{command}':\n#{output}")
        else
          changes_required = true
        end
      when *resource[:warnings_ret]
        raise(Puppet::Error, "#{resource[:name]}:\n\n#{output}")
      else
        raise(Puppet::Error, "#{resource[:name]}: Command exited with error (#{status.exitstatus}): '#{command}':\n\n#{output}")
      end

      # Return array of values...
      [changes_required, output]
    end

  end

  autorequire(:file) do
    [Pathname.new(self[:deploy_path]).parent]
  end

  autorequire(:user) do
    [self[:owner]]
  end

  autorequire(:group) do
    [self.groupname]
  end

  validate do
    check_things = [self[:script_name], self[:deploy_path], self[:owner]]
    check_list = check_things.join(",")
    check_things.each do | item |
      unless item
        raise(Puppet::Error, "#{self[:name]}: (#{check_list}), are all required attributes - missing #{item}:#{item.value}")
      end
    end
  end

  def validate_ret_code(value)
    values = [value] unless value.is_a? Array
    values.each do |value|
      unless value =~ /^\d+$/
        raise ArgumentError, "The return code(s) must be integers not:'#{value}'"
      end
    end 
  end

  def flush
    # We need to ensure all data is in place before final script run
    @parameters[:files].flush
    @parameters[:exec].flush
  end

  def md5_content(content)
    md5(content)
  end

  def exist?
    value = true
    self[:files_content].keys do | file_name |
      file_path = File.join(self[:deploy_path], file_name)
      if !File.exists?(file_path)
        value = false
        break
      end
    end
    if !File.exists?(self[:deploy_path])
      value = false
    end
    value
  end

  def content_retrieve(file, md5munge=false)
    if !File.exists?(file)
      if md5munge
        return [:absent, :absent]
      else
        return :absent
      end
    end
    begin
      # Audit the current file here!
      content = File.open(file).read
      if md5munge
        [md5(content), content]
      else
        content
      end
    rescue => detail
      raise(Puppet::Error, "Could not read #{file} #{self.title}: #{detail}")
    end
  end

  def save_files(deploy_path)
    self[:files_content].each do | file_name, intended_content |
      file_path = File.join(deploy_path, file_name)
      script_path = File.join(deploy_path, self[:script_name])
      self.save_content(file_path, intended_content, deploy_path)

      # Now change perms as required
      begin
        mode = 0644
        mode = 0755 if file_path == script_path
        File.chmod(mode, file_path)
      rescue => detail
        raise(Puppet::Error, "#{self.title}: Could not set permissions #{file_path}: #{detail}")
      end
    end
  end

  def save_content(file_path, content, deploy_path)
    begin
      self.mk_path(file_path, deploy_path)

      File.open(file_path, 'w') do | file |
        file.puts(content)
      end

      self.chown(file_path)
    rescue => detail
      raise(Puppet::Error, "#{self.title}: Could not create #{file_path}: #{detail}")
    end
  end

  def content_diff(file_path, content, tag='', mode=nil)
    self.write_temporarily(content, 'intended-content-') do |tmp_intended_content_path|
      notice "\n" + diff(file_path, tmp_intended_content_path)
    end
  end

  def mk_path(file_path, deploy_path)
    path = Pathname.new(file_path).parent
    unless File.directory?(Pathname.new(deploy_path).parent)
      raise(Puppet::Error, 
            "#{self[:name]}: Won't create directory as parent doesn't exist: '#{deploy_path}'")
    end
    if !File.directory?(path)
      FileUtils.mkdir_p(path, :mode => 0755)
      self.chown(path)
    end
  end

  def chown(path)
    begin
      user = Etc.getpwnam(self[:owner])
      uid = self.userstruct.uid
      gid = self.userstruct.gid
      File.chown(uid, gid, path)
    rescue Puppet::Error
      throw
    rescue => detail
      raise(Puppet::Error, 
            "#{self[:name]}: Can't set permissions (uid:'#{uid}', gid@:'#{gid}') for file:#{path}':#{detail}")
    end
  end

  def groupname
    begin
      groupname = self.userstruct.gid
    rescue => detail
      groupname = nil
    end
    groupname
  end

  def userstruct
    begin
      user = Etc.getpwnam(self[:owner])
    rescue TypeError, ArgumentError
      raise(Puppet::Error, "#{self[:name]}: Can't access user details for user:'#{self[:owner]}'")
    end
  end

  def write_temporarily(content, tag='', mode=nil)
    begin
      tempfile = Tempfile.new("puppet-file-#{tag}")
      tempfile.open

      tempfile.puts(content)
      tempfile.close
      new_file = nil
      if Puppet[:debug]
        new_file = "#{tempfile.path}-keep"
        FileUtils.cp(tempfile.path, new_file)
      else
        new_file = tempfile.path
      end
      File.chmod(mode, new_file) if !mode.nil?
    rescue => detail
      raise(Puppet::Error, "#{self.title}: Could not write to file #{new_file}: #{detail}")
    end
    yield new_file
    tempfile.delete
  end

end
