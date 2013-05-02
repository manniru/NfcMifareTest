package org.nfc.mifare;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class NfcMifareActivity extends Activity {
    private static final String TAG = NfcMifareActivity.class.getSimpleName();
    private static final String LINE_SEPARATOR = System.getProperty("line.separator", "\n");

    private boolean mDebug = true;

    private String mCharset = "ISO-8859-1";
    private boolean mShowDataAsHexString;
    private boolean mReadAll;

    private boolean mWriteToBlock;
    private boolean mWriteAll;

    private NfcAdapter mAdapter;
    private PendingIntent mPendingIntent;
    private IntentFilter[] mIntentFilters;
    private String[][] mTechList;

    private EditText mReadBlockIndex;
    private RadioGroup mReadOptions;
    private CheckBox mReadAllData;

    private EditText mWriteBlockContent;
    private RadioGroup mWriteOptions;
    private EditText mWriteBlockIndex;

    private CheckBox mDebugCheckBox;

    private RelativeLayout mWriteBlockIndexLayout;

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.nfc);

        mAdapter = NfcAdapter.getDefaultAdapter(this);
        if (mAdapter == null) {
            this.finish();
            return;
        }

        mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        IntentFilter filter = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        try {
            filter.addDataType("*/*");
        } catch (IntentFilter.MalformedMimeTypeException e) {
            e.printStackTrace();
        }
        mIntentFilters = new IntentFilter[]{filter};
        mTechList = new String[][]{new String[]{MifareClassic.class.getName()}};

        initViews();
    }

    @Override
    protected void onResume() {
        super.onResume();
        mAdapter.enableForegroundDispatch(this, mPendingIntent, mIntentFilters, mTechList);
    }

    @Override
    protected void onPause() {
        super.onPause();
        mAdapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        if (!NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            return;
        }
        resolveIntent(intent);
    }

    private void resolveIntent(Intent intent) {
        debug("resolveIntent...", false);
        if (getText(mReadBlockIndex) == null && getText(mWriteBlockContent) == null && !mReadAll) {
            debug(getString(R.string.toast_need_data), true);
            return;
        }

        MifareClassic mfc = MifareClassic.get((Tag) intent.getParcelableExtra(NfcAdapter.EXTRA_TAG));
        if (mfc == null) {
            debug(getString(R.string.toast_not_mifare_classic), true);
            return;
        }

        disableAllOptions();
        try {
            String result1 = performRead(mfc);
            if (result1 != null) {
                if (mReadAll) {
                    alert(result1);
                } else {
                    debug(result1, true);
                }
            }

            List<Integer> result2 = performWrite(mfc);
            if (result2 != null) {
                if (result2.size() == 0) {
                    debug(getString(R.string.toast_write_success), true);
                } else if (result2.size() == 1 && !mReadAll) {
                    debug(getString(R.string.toast_write_fail), true);
                } else {
                    StringBuilder sb = new StringBuilder();
                    sb.append(getString(R.string.result_failed_the_following));
                    sb.append(LINE_SEPARATOR);
                    for (int i = 0; i < result2.size(); i++) {
                        sb.append(result2.get(i));
                        if (i != 0 && i % 5 == 0) {
                            sb.append(LINE_SEPARATOR);
                        } else {
                            sb.append(", ");
                        }
                    }
                    sb.delete(sb.length() - 2, sb.length());
                    alert(sb.toString());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            enableAllOptions();
            try {
                mfc.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String performRead(MifareClassic mfc) throws IOException {
        if (getText(mReadBlockIndex) == null && !mReadAll) {
            return null;
        }
        if (!mfc.isConnected()) {
            mfc.connect();
        }

        String ret = null;
        if (mReadAll) {
            StringBuilder sb = new StringBuilder();
            boolean auth;
            int blockCount = mfc.getBlockCount();
            for (int i = 0; i < blockCount; i++) {
                auth = mfc.authenticateSectorWithKeyA(mfc.blockToSector(i), MifareClassic.KEY_DEFAULT);
                if (auth) {
                    byte[] data = readBlock(mfc, i);
                    sb.append(String.format(getString(R.string.block_index_dynamic), i));
                    sb.append(LINE_SEPARATOR);
                    sb.append(convertBytes2String(data));
                    sb.append(LINE_SEPARATOR);
                    sb.append(LINE_SEPARATOR);
                }
            }
            sb.delete(sb.length() - 2, sb.length());
            ret = sb.toString();
        } else {
            int blockIndex = Integer.parseInt(getText(mReadBlockIndex));
            if (!validateBlockIndex(mfc, blockIndex)) {
                debug(getString(R.string.err_block_index_out_of_bound), true);
                return ret;
            }
            int sectorIndex = mfc.blockToSector(blockIndex);
            boolean auth = mfc.authenticateSectorWithKeyA(sectorIndex, MifareClassic.KEY_DEFAULT);
            if (auth) {
                byte[] data = readBlock(mfc, blockIndex);
                ret = convertBytes2String(data);
            } else {
                debug(getString(R.string.auth_failed), true);
            }
        }
        return ret;
    }

    private List<Integer> performWrite(MifareClassic mfc) throws IOException {
        if (getText(mWriteBlockContent) == null) {
            return null;
        }

        if (!mfc.isConnected()) {
            mfc.connect();
        }

        List<Integer> ret = new ArrayList<Integer>();
        String content = getText(mWriteBlockContent);
        if (mWriteAll) {
            for (int i = 1; i < mfc.getBlockCount(); i++) {
                if ((i + 1) % 4 == 0) {
                    continue;
                }
                boolean auth = mfc.authenticateSectorWithKeyA(mfc.blockToSector(i), MifareClassic.KEY_DEFAULT);
                if (auth) {
                    writeBlock(mfc, i, convertString2Bytes(content));
                } else {
                    ret.add(i);
                }
            }
        } else {
            int blockIndex;
            if (mWriteToBlock && getText(mWriteBlockIndex) != null) {
                blockIndex = Integer.parseInt(getText(mWriteBlockIndex));
                if (!validateBlockIndex(mfc, blockIndex)) {
                    debug(getString(R.string.err_block_index_out_of_bound), true);
                    return null;
                }
                if (blockIndex == 0 || (blockIndex + 1) % 4 == 0) {
                    debug(getString(R.string.err_write_to_forbidden_block), true);
                    return null;
                }
            } else {
                blockIndex = randomBlockIndex(mfc);
            }
            debug(String.format(getString(R.string.write_random_dynamic), blockIndex), false);
            boolean auth = mfc.authenticateSectorWithKeyA(mfc.blockToSector(blockIndex), MifareClassic.KEY_DEFAULT);
            if (auth) {
                writeBlock(mfc, blockIndex, convertString2Bytes(content));
            } else {
                ret.add(blockIndex);
                debug(getString(R.string.auth_failed), true);
            }
        }
        return ret;
    }

    private byte[] readBlock(MifareClassic mfc, int blockIndex) throws IOException {
        return mfc.readBlock(blockIndex);
    }

    private void writeBlock(MifareClassic mfc, int blockIndex, byte[] data) throws IOException {
        mfc.writeBlock(blockIndex, data);
    }

    private String convertBytes2String(byte[] data) throws UnsupportedEncodingException {
        String ret;
        if (mShowDataAsHexString) {
            StringBuilder sb = new StringBuilder();
            for (byte b : data) {
                int i = (int) b;
                sb.append(Integer.toHexString(i).toUpperCase());
            }
            ret = sb.toString();
        } else {
            int pos = data.length;
            for (int i = data.length - 1; i >= 0; i--) {
                if (data[i] != 0) {
                    break;
                }
                pos = i;
            }
            ret = new String(data, 0, pos, mCharset);
        }
        return ret;
    }

    private byte[] convertString2Bytes(String content) throws UnsupportedEncodingException {
        byte[] ret = new byte[16];
        byte[] buf = content.getBytes(mCharset);
        int retLen = ret.length;
        int bufLen = buf.length;
        boolean b = retLen > bufLen;

        for (int i = 0; i < retLen; i++) {
            if (b && i >= bufLen) {
                ret[i] = 0;
                continue;
            }
            ret[i] = buf[i];
        }
        return ret;
    }

    private String getText(EditText et) {
        if (TextUtils.isEmpty(et.getText())) {
            return null;
        }
        return et.getText().toString().trim();
    }

    private int randomBlockIndex(MifareClassic mfc) {
        int i = new Random().nextInt(mfc.getBlockCount());
        if (i == 0 || (i + 1) % 4 == 0) {
            return randomBlockIndex(mfc);
        }
        return i;
    }

    private boolean validateBlockIndex(MifareClassic mfc, int blockIndex) {
        if (blockIndex >= mfc.getBlockCount()) {
            return false;
        }
        return true;
    }

    private void alert(String msg) {
        new AlertDialog.Builder(this).setMessage(msg).show();
    }

    private void enableAllOptions() {
        mReadBlockIndex.setEnabled(true);
        for (int i = 0; i < mReadOptions.getChildCount(); i++) {
            mReadOptions.getChildAt(i).setEnabled(true);
        }
        mReadAllData.setEnabled(true);

        mWriteBlockContent.setEnabled(true);
        for (int i = 0; i < mWriteOptions.getChildCount(); i++) {
            mWriteOptions.getChildAt(i).setEnabled(true);
        }
        mWriteBlockIndex.setEnabled(true);

        mDebugCheckBox.setEnabled(true);
    }

    private void disableAllOptions() {
        mReadBlockIndex.setEnabled(false);
        for (int i = 0; i < mReadOptions.getChildCount(); i++) {
            mReadOptions.getChildAt(i).setEnabled(false);
        }
        mReadAllData.setEnabled(false);

        mWriteBlockContent.setEnabled(false);
        for (int i = 0; i < mWriteOptions.getChildCount(); i++) {
            mWriteOptions.getChildAt(i).setEnabled(false);
        }
        mWriteBlockIndex.setEnabled(false);

        mDebugCheckBox.setEnabled(false);
    }

    public void clearText(View view) {
        switch (view.getId()) {
            case R.id.btn_et_read_block_index:
                mReadBlockIndex.setText(null);
                break;

            case R.id.btn_write_block_content:
                mWriteBlockContent.setText(null);
                break;

            case R.id.btn_write_block_index:
                mWriteBlockIndex.setText(null);
                break;
        }
    }

    private void initViews() {
        mReadBlockIndex = (EditText) findViewById(R.id.et_read_block_index);
        mReadOptions = (RadioGroup) findViewById(R.id.rg_read_options);
        mReadAllData = (CheckBox) findViewById(R.id.cb_read_all_data);

        mWriteBlockContent = (EditText) findViewById(R.id.et_write_block_content);
        mWriteOptions = (RadioGroup) findViewById(R.id.rg_write_options);
        mWriteBlockIndex = (EditText) findViewById(R.id.et_write_block_index);

        mDebugCheckBox = (CheckBox) findViewById(R.id.cb_debug);

        mWriteBlockIndexLayout = (RelativeLayout) findViewById(R.id.rl_write_block_index);

        mReadAllData.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                mReadAll = isChecked;
            }
        });

        mReadOptions.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                switch (checkedId) {
                    case R.id.rb_charset_ascii:
                        mCharset = "ISO-8859-1";
                        mShowDataAsHexString = false;
                        break;

                    case R.id.rb_charset_utf8:
                        mCharset = "UTF-8";
                        mShowDataAsHexString = false;
                        break;

                    case R.id.rb_hex:
                        mCharset = "ISO-8859-1";
                        mShowDataAsHexString = true;
                        break;
                }
            }
        });

        mWriteOptions.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                switch (checkedId) {
                    case R.id.rb_write_block_index:
                        mWriteBlockIndexLayout.setVisibility(View.VISIBLE);
                        mWriteToBlock = true;
                        mWriteAll = false;
                        break;

                    case R.id.rb_write_all_data:
                        mWriteBlockIndexLayout.setVisibility(View.GONE);
                        mWriteToBlock = false;
                        mWriteAll = true;
                        break;
                }
            }
        });

        mDebugCheckBox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                mDebug = !isChecked;
            }
        });
    }

    private void debug(String info, boolean toast) {
        if (mDebug) {
            Log.i(TAG, info);
            if (toast) {
                showToast(info);
            }
        }
    }

    private void showToast(String toast) {
        Toast.makeText(this, toast, Toast.LENGTH_SHORT).show();
    }
}
