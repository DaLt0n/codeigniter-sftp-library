<?php

/**
 * SFTP Class
 *
 * This content is released under the MIT License (MIT)
 *
 * Copyright (c) 2017, ChillyOrange
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author      ChillyOrange Devs Team
 * @copyright   Copyright (c) 2017, ChillyOrange (https://chillyorange.com/)
 * @license     http://opensource.org/licenses/MIT  MIT License
 * @link        https://github.com/chillyorange/codeigniter-sftp-library
 * @since       Version 1.0.0
 */
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * Sftp Class
 *
 * This class enables you to use sFTP methods
 * as like as CodeIgniter's default FTP Library
 *
 * @package     CodeIgniter
 * @subpackage  Libraries
 * @category    Libraries
 * @author      ChillyOrange Devs Team
 * @link        https://github.com/chillyorange/codeigniter-sftp-library
 */

/**
 * Dependencies: yum install libssh2.x86_64 libssh2-devel.x86_64 ; pecl install ssh2
 */
class Sftp {

    var $hostname       = '';       // the hostname of the server
    var $username       = '';       // username of the server
    var $password       = '';       // password of the server
    var $pubkeyfile     = '';       // path to your public key file (e.g. /Users/username/.ssh/id_rsa.pub)
    var $prikeyfile     = '';       // path to your private key file (e.g. /Users/username/.ssh/id_rsa)
    var $passphrase      = '';       // the passphrase of your key (leave blank if you don't have one)
    var $port           = 22;
    var $method         = 'auth';    // By default login via username/password
    var $debug          = true;
    var $conn           = false;
    var $sftp           = false;
    var $error_message  = '';


    /**
     * Constructor - Sets Preferences
     *
     * The constructor can be passed an array of config values
     *
     * @version 1.0.0
     */
    public function __construct($config = array())
    {
        if (count($config) > 0)
        {
            $this->initialize($config);
        }

        log_message('debug', "sFTP Class Initialized");
        // Make sure that the SSH2 pecl is installed
        if ( ! function_exists('ssh2_connect'))
        {
            log_message('error', "SSH2 PECL is not installed");
            exit();
        }
    }

    // --------------------------------------------------------------------

    /**
     * Initialize preferences
     *
     * @version 1.0.0
     * @access  public
     * @param   array
     * @return  void
     */
    public function initialize($config = array())
    {
        foreach ($config as $key => $val)
        {
            if (isset($this->$key))
            {
                $this->$key = $val;
            }
        }

        // Prep the hostname
        $this->hostname = preg_replace('|.+?://|', '', $this->hostname);
    }

    // --------------------------------------------------------------------

    /**
     * SFTP Connect
     *
     * @version 1.0.0
     * @access  public
     * @param   array    the connection values
     * @return  bool
     */
    public function connect($config = array())
    {
        if (count($config) > 0)
        {
            $this->initialize($config);
        }

        // Open up SSH connection to server with supplied credetials.
        $this->conn = @ssh2_connect($this->hostname, $this->port);

        // Try and login...
        if ( ! $this->_login())
        {
            $this->_error('sftp_unable_to_login_to_ssh');
            return FALSE;
        }

        // Once logged in successfully, try to open SFTP resource on remote system.
        // If successful, set this resource as a global variable.
        if (FALSE === ($this->sftp = @ssh2_sftp($this->conn)))
        {
            $this->_error('sftp_unable_to_open_sftp_resource');
            return FALSE;
        }

        return TRUE;
    }

    // --------------------------------------------------------------------

    /**
     * SFTP Login (Passphrase callback not supported on libssh2, everything works if you dont need to authenticate with passphrase, alternative: phpseclib)
     *
     * @version 1.0.0
     * @access  private
     * @return  bool
     */
    private function _login()
    {
        if ($this->method == 'key') {
            if ($this->passphrase != '') {
                return @ssh2_auth_pubkey_file($this->conn, $this->username, $this->pubkeyfile, $this->prikeyfile, $this->passphrase);
            }
            return @ssh2_auth_pubkey_file($this->conn, $this->username, $this->pubkeyfile, $this->prikeyfile);
        } else {
            return @ssh2_auth_password($this->conn, $this->username, $this->password);
        }
    }

    // --------------------------------------------------------------------

    /**
     * Validates the connection ID (both SSH and SFTP)
     *
     * @version 1.0.0
     * @access  private
     * @return  bool
     */
    private function _is_conn()
    {
        if ( ! is_resource($this->conn) && ! is_resource($this->sftp))
        {
            $this->_error('sftp_no_connection');
            return FALSE;
        }
        return TRUE;
    }

    // --------------------------------------------------------------------


    /**
     * Change directory
     *
     * The second parameter lets us momentarily turn off debugging so that
     * this function can be used to test for the existence of a folder
     * without throwing an error.  There's no FTP equivalent to is_dir()
     * so we do it by trying to change to a particular directory.
     * Internally, this parameter is only used by the "mirror" function below.
     *
     * @version 1.0.0
     * @access  public
     * @param   string
     * @param   bool
     * @return  bool
     */
    public function changedir($path = '', $supress_debug = FALSE)
    {
        if ($path == '' OR ! $this->_is_conn())
        {
            return FALSE;
        }

        $result = @ssh2_sftp_stat($this->sftp, $path);

        if ($result === FALSE)
        {
            if ($supress_debug == FALSE)
            {
                $this->_error('sftp_unable_to_changedir'); /// change this error
            }
            return FALSE;
        }

        return TRUE;
    }

    /**
     * Get file info
     */
    public function get_file_info($path = '') {
        if ($path == '' OR ! $this->_is_conn())
        {
            return FALSE;
        }

        return @ssh2_sftp_stat($this->sftp, $path);
    }

    // --------------------------------------------------------------------

    /**
     * Create a directory
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $path
     * @param   integer $permissions
     * @return  bool
     */
    public function mkdir($path = '', $permissions = 0777)
    {
        if ($path == '' || ! $this->_is_conn())
        {
            return FALSE;
        }

        $result = @ssh2_sftp_mkdir($this->sftp, $path, $permissions, TRUE);

        if ($result === FALSE)
        {
            $this->_error('sftp_unable_to_mkdir');
            return FALSE;
        }

        return TRUE;
    }


    // --------------------------------------------------------------------

    /**
     * Upload a file to the server
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $locpath
     * @param   string  $rempath
     * @param   string  $mode
     * @param   integer $permissions
     * @return  bool
     */
    public function upload($locpath, $rempath, $permissions = null)
    {
        if ( ! $this->_is_conn())
        {
            return FALSE;
        }

        if ( ! file_exists($locpath))
        {
            $this->_error('sftp_no_source_file');
            return FALSE;
        }

        if (! ssh2_scp_send($this->conn, $locpath, $rempath)) {
            $this->_error('sftp_unable_to_upload');
            return FALSE;
        }
        if (!empty($permissions)) {
            if (! $this->chmod($rempath, $permissions)) {
                $this->_error('sftp_unable_to_chmod');
            }
        }
        return TRUE;
    }

    // --------------------------------------------------------------------

    /**
     * Download a file from a remote server to the local server
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $rempath
     * @param   string  $locpath
     * @param   string  $mode
     * @return  bool
     */
    public function download($rempath, $locpath, $mode = 'auto')
    {
        if ( ! $this->_is_conn())
        {
            return FALSE;
        }

        if (! ssh2_scp_recv($this->conn, $rempath, $locpath)) {
            $this->_error('sftp_unable_to_download');
            return FALSE;
        }
        return TRUE;
    }

    // --------------------------------------------------------------------

    /**
     * Rename (or move) a file
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $old_file
     * @param   string  $new_file
     * @param   bool    $move
     * @return  bool
     */
    public function rename($old_file, $new_file, $move = FALSE)
    {
        if ( ! $this->_is_conn())
        {
            return FALSE;
        }

        $result = @ssh2_sftp_rename($this->sftp, $old_file, $new_file);

        if ($result === FALSE)
        {
            $msg = ($move == FALSE) ? 'sftp_unable_to_rename' : 'sftp_unable_to_move';
            $this->_error($msg);
            return FALSE;
        }

        return TRUE;
    }

    // --------------------------------------------------------------------

    /**
     * Move a file
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $old_file
     * @param   string  $new_file
     * @return  bool
     */
    public function move($old_file, $new_file)
    {
        return $this->rename($old_file, $new_file, TRUE);
    }

    // --------------------------------------------------------------------

    /**
     * Rename (or move) a file
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $filepath
     * @return  bool
     */
    public function delete_file($filepath)
    {
        if ( ! $this->_is_conn())
        {
            return FALSE;
        }

        $result = @ssh2_sftp_unlink($this->sftp, $filepath);

        if ($result === FALSE)
        {
            $this->_error('sftp_unable_to_delete');
            return FALSE;
        }

        return TRUE;
    }

    // --------------------------------------------------------------------

    /**
     * Delete a folder and recursively delete everything (including sub-folders)
     * containted within it.
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $filepath
     * @return  bool
     */
    public function delete_dir($filepath)
    {
        if ( ! $this->_is_conn())
        {
            return FALSE;
        }

        // Add a trailing slash to the file path if needed
        $filepath = preg_replace("/(.+?)\/*$/", "\\1/",  $filepath);

        $list = $this->list_files($filepath);

        if ($list !== FALSE AND count($list) > 0)
        {
            foreach ($list as $item)
            {
                // If we can't delete the item it's probaly a folder so
                // we'll recursively call delete_dir()
                if ( ! @ssh2_sftp_rmdir($this->sftp, $item))
                {
                    $this->delete_dir($item);
                }
            }
        }

        $result = @ssh2_sftp_rmdir($this->sftp, $filepath);

        if ($result === FALSE)
        {
            $this->_error('sftp_unable_to_delete');
            return FALSE;
        }

        return TRUE;
    }

    // --------------------------------------------------------------------

    /**
     * Set file permissions
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $path
     * @param   string  $perm
     * @return  bool
     */
    public function chmod($path, $perm)
    {
        if ( ! $this->_is_conn())
        {
            return FALSE;
        }

        // Permissions can only be set when running PHP 5
        if ( ! function_exists('ssh2_sftp_chmod'))
        {
            $this->_error('sftp_unable_to_chmod');
            return FALSE;
        }

        $result = @ssh2_sftp_chmod($this->sftp, $path, $perm);

        if ($result === FALSE)
        {
            $this->_error('sftp_unable_to_chmod');
            return FALSE;
        }

        return TRUE;
    }

    // --------------------------------------------------------------------

    /**
     * sFTP List files in the specified directory
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $path
     * @return  array
     */
    public function list_files($path = null, $options = [])
    {

        if ( ! $this->_is_conn())
        {
            return FALSE;
        }

        $results = array();

        $sftp = intVal($this->sftp);
        $files = $this->_scan_directory("ssh2.sftp://{$sftp}/{$path}");

        // exclude '.' and '..' from list of files
        foreach ($files as $file)
        {
            if ($file != '.' || $file != '..')
            {
                if (!empty($options['details']) || !empty($options['sortby'])) {
                    // get file info
                    $detail = $this->get_file_info($file);
                    // prepare file info
                    $results[] = [
                        'name' => $file,
                        'size' => !empty($detail['size']) ? $detail['size'] : null,
                        'mtime' => !empty($detail['mtime']) ? date("Y-m-d H:i:s", $detail['mtime']) : null,
                        'atime' => !empty($detail['atime']) ? date("Y-m-d H:i:s", $detail['atime']) : null,
                    ];
                } else {
                    $results[] = $file;
                }
            }
        }
        // sort results
        if (!empty($options['sortby'])) {
            $sort_type = @current($options['sortby']);
            $sort_key = @key($options['sortby']);
            if (in_array($sort_key, ['name','size','mtime','atime'])) {
                usort($results, function ($a, $b) use ($sort_type, $sort_key) {
                    if ($a[$sort_key] == $b[$sort_key]) {
                        return 0;
                    }
                    if ($sort_type == 'asc') {
                        return ($a[$sort_key] < $b[$sort_key]) ? -1 : 1;
                    } else {
                        return ($a[$sort_key] > $b[$sort_key]) ? -1 : 1;
                    }
                });
            }
        }

        return $results;
    }

    // ------------------------------------------------------------------------

    /**
     * Scans a directory from a given path
     *
     * @version 1.0.0
     * @access  private
     * @param   string  $dir
     * @param   bool    $recursive
     * @return  array
     */

    function _scan_directory($dir, $recursive = FALSE)
    {
        $tempArray = array();
        $handle = @opendir($dir);
        // List all the files
        if (!empty($handle)) {
            while (false !== ($file = readdir($handle))) {
                if (substr("$file", 0, 1) != "."){
                    if(is_dir($file) && $recursive){
                        // If its a directory, interate again
                        $tempArray[$file] = $this->_scan_directory("$dir/$file");
                    } else {
                        $tempArray[] = $file;
                    }
                }
            }
        }

        closedir($handle);
        return $tempArray;
    }
    // --------------------------------------------------------------------

    /**
     * Read a directory and recreate it remotely
     *
     * This function recursively reads a folder and everything
     * it contains (including sub-folders) and creates a mirror
     * via FTP based on it.  Whatever the directory structure
     * of the original file path will be recreated on the server.
     *
     * @version 1.0.0
     * @access  public
     * @param   string  $locpath    source path with trailing slash
     * @param   string  $rempath    destination path - real path with trailing slash
     * @return  bool
     */
    public function mirror($locpath, $rempath)
    {
        if ( ! $this->_is_conn())
        {
            $this->_error('sftp_connection_problem');
            return FALSE;
        }

        // Open the local file path
        if ($fp = @opendir($locpath))
        {
            // Attempt to open the remote file path.
            if ( ! $this->changedir($rempath, TRUE))
            {
                // If it doesn't exist we'll attempt to create the direcotory
                if ( ! $this->mkdir($rempath) OR ! $this->changedir($rempath))
                {
                    return FALSE;
                }
            }

            // Recursively read the local directory
            while (FALSE !== ($file = readdir($fp)))
            {
                //print_r($file); die();
                if (@is_dir($locpath.$file) && substr($file, 0, 1) != '.')
                {
                    $this->mirror($locpath.$file."/", $rempath.$file."/");
                }
                elseif (substr($file, 0, 1) != ".")
                {
                    // Get the file extension so we can se the upload type
                    $ext = $this->_getext($file);
                    $mode = $this->_settype($ext);

                    $this->upload($locpath.$file, $rempath.$file, $mode);
                }
            }
            return TRUE;
        }

        return FALSE;
    }

    // --------------------------------------------------------------------

    /**
     * Get users remote home full path
     *
     */
    public function get_home_path()
    {
        $stream = ssh2_exec($this->conn, 'pwd');
        // Enable blocking for streams
        stream_set_blocking($stream, true);
        return trim(stream_get_contents($stream));
    }

    /**
     * Extract the file extension
     *
     * @version 1.0.0
     * @access  private
     * @param   string
     * @return  string
     */
    private function _getext($filename)
    {
        if (FALSE === strpos($filename, '.'))
        {
            return 'txt';
        }

        $x = explode('.', $filename);
        return end($x);
    }

    // --------------------------------------------------------------------

    /**
     * Set the upload type
     *
     * @version 1.0.0
     * @access  private
     * @param   string
     * @return  string
     */
    private function _settype($ext)
    {
        $text_types = array(
            'txt',
            'text',
            'php',
            'phps',
            'php4',
            'js',
            'css',
            'htm',
            'html',
            'phtml',
            'shtml',
            'log',
            'xml'
        );


        return (in_array($ext, $text_types)) ? 'ascii' : 'binary';
    }

    // ------------------------------------------------------------------------

    /**
     * Close the connection
     *
     * @version 1.0.0
     * @access  public
     * @param   string  path to source
     * @param   string  path to destination
     * @return  bool
     */
    public function close()
    {
        if ( ! $this->_is_conn())
        {
            return FALSE;
        }

        ssh2_exec($this->conn, 'exit');
        unset($this->conn);

        return TRUE;
    }

    /**
     * Show error
     */
    public function get_errors() {
        return $this->error;
    }

    // ------------------------------------------------------------------------

    /**
     * Display error message
     *
     * @version 1.0.0
     * @access  private
     * @param   string
     * @return  bool
     */
    private function _error($line)
    {
        $error_message = [
            'sftp_unable_to_login_to_ssh' => 'unable to login to ssh',
            'sftp_unable_to_open_sftp_resource' => 'unable to login to ssh',
            'sftp_no_connection' => 'unable to login to ssh',
            'sftp_unable_to_changedir' => 'unable to changedir',
            'sftp_unable_to_mkdir' => 'unable to mkdir',
            'sftp_no_source_file' => 'no source file',
            'sftp_unable_to_upload' => 'unable to upload',
            'sftp_unable_to_download' => 'unable to download',
            'sftp_unable_to_delete' => 'unable to delete',
            'sftp_unable_to_chmod' => 'unable to chmod',
            'sftp_invalid_path' => 'invalid path',
            'sftp_connection_problem' => 'connection problem',
        ];
        // set error
        $this->error = !empty($error_message[$line]) ? $error_message[$line] : 'unknown error';
        // show error (debug)
        if ($this->debug) show_error($this->error);
    }


}

// END SFTP Class

/* End of file Sftp.php */
/* Location: ./application/libraries/Sftp.php */