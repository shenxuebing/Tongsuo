#!/usr/bin/env perl
# Tongsuo API 序号自动分配脚本
# 用法:
#   perl util/tongsuo_num_add.pl <符号名> <功能标签> [<符号名> <标签> ...]
#
# 示例:
#   perl util/tongsuo_num_add.pl TSAPI_SDF_OpenDevice SM2
#   perl util/tongsuo_num_add.pl TSAPI_SM2Sign "SM2,SM3" TSAPI_SM3 SM3
#
# 功能标签: SM2, SM3, SM4, SM2_THRESHOLD, TSAPI, (空) 等
#
# 序号策略: Tongsuo 符号从 9000 开始，避免与上游 OpenSSL 冲突

use strict;
use warnings;

my $num_file = "util/libcrypto.num";
my $tongsuo_start = 9000;

die "用法: perl $0 <符号名> <功能标签> [<符号名> <标签> ...]\n" if @ARGV == 0;
die "符号名和功能标签必须成对出现\n" if @ARGV % 2 != 0;

# 读取现有文件
open(my $fh, '<', $num_file) or die "无法打开 $num_file: $!\n";
my @lines = <$fh>;
close($fh);

# 找到 Tongsuo 已有最大序号 (>= 9000)
my $max_tongsuo = $tongsuo_start - 1;
for my $line (@lines) {
    if ($line =~ /^(\S+)\s+(\d+)\s+/) {
        my $ord = $2;
        $max_tongsuo = $ord if $ord >= $tongsuo_start && $ord > $max_tongsuo;
    }
}

my @new_entries;
while (@ARGV >= 2) {
    my $sym = shift @ARGV;
    my $tags = shift @ARGV;

    # 检查是否已存在
    my $exists = 0;
    for my $line (@lines) {
        if ($line =~ /^$sym\s+/) {
            print "警告: $sym 已存在，跳过\n";
            $exists = 1;
            last;
        }
    }
    next if $exists;

    $max_tongsuo++;

    my $tag_str = length($tags) ? $tags : "";
    my $entry = sprintf "%-45s %5d\t3_5_4\tEXIST::FUNCTION:%s", $sym, $max_tongsuo, $tag_str;
    push @new_entries, $entry;
}

# 追加到文件
open($fh, '>>', $num_file) or die "无法写入 $num_file: $!\n";
print $fh "\n# Tongsuo 扩展: 自动添加 (" . localtime() . ")\n";
for my $entry (@new_entries) {
    print $fh "$entry\n";
}
close($fh);

print "已添加 " . scalar(@new_entries) . " 个符号，最大序号: $max_tongsuo\n";
for my $entry (@new_entries) {
    print "  $entry\n";
}